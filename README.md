# armory

A JavaScript emulator of the [USB Armory](https://github.com/usbarmory/usbarmory)
hardware security module. It implements the same IPC protocol and security
model that the physical device exposes, allowing the rest of the system to be
developed and tested without hardware present. When a USB Armory unit is
available, this daemon is replaced by the device; no changes are required in
callers.

The daemon owns a BIP-39 mnemonic, derives addresses from it, and signs hashes
on behalf of callers — while enforcing a hardcoded destination policy that
callers cannot override.

The mnemonic never leaves the process. Callers send a hash; they get a
secp256k1 signature back.

---

## Concepts

### Mnemonic and key material

Armory holds a single BIP-39 mnemonic. All signing keys are derived from it
via BIP-32/BIP-44 paths. The mnemonic is stored at rest in `.keys/mnemonic.enc`,
encrypted with `ARMORY_KEY` using Argon2id + AES-256-CBC.

`ARMORY_KEY` is a 32-byte (64 hex char) secret stored in `.env`. It is the
only value that must be provided to start the daemon. If it is lost, the
mnemonic cannot be recovered from disk.

### Internal address pool

At startup, armory pre-derives two parallel address sequences from the mnemonic:

| Range | BIP-44 path | Format |
|-------|-------------|--------|
| EVM | `m/44'/60'/0'/0/<index>` | `0x...` EIP-55 checksummed |
| Cosmos | `m/44'/118'/0'/0/<index>` | `cosmos1...` bech32 |

Both sequences run from index 0 to `ARMORY_POOL_SIZE - 1` (default 10 000).
These are the **internal addresses**. Only transfers between internal addresses
are permitted. Transfers out of the pool require an external whitelist entry.

### Index tiers

The pool is split into two tiers that control transfer permissions:

| Tier | Indices | Can transfer to |
|------|---------|-----------------|
| Staging | 0 – 49 | High-value only (indices 50 – 99) |
| High-value | 50+ | Any internal address |

Staging accounts receive funds from outside but cannot move them arbitrarily —
they can only push to high-value accounts, which act as a buffer.

### Action whitelist

Only the following action types can be signed. Any other `actionType` string
is rejected with `err sign request denied`.

| Action type | Category | Notes |
|-------------|----------|-------|
| `approveAgent` | auth | Authorize an ephemeral agent key on Hyperliquid |
| `usdSend` | transfer | USDC peer-to-peer on HL L2 |
| `spotSend` | transfer | Spot token (HYPE, etc.) peer-to-peer on HL L2 |
| `withdraw3` | withdrawal | HL L2 → external L1 (USDC or any spot token) |
| `transfer` | transfer | ERC-20 or native send to internal address |
| `evmWithdraw` | withdrawal | ERC-20 or native send to external whitelist |
| `AddAuthenticator` | auth | Register permissioned trading key on dYdX |
| `RemoveAuthenticator` | auth | Revoke permissioned trading key on dYdX |
| `MsgTransfer` | transfer | Between accounts on dYdX |
| `MsgSend` | transfer | Native token send on dYdX (gas distribution) |
| `MsgWithdrawFromSubaccount` | withdrawal | dYdX subaccount withdrawal |

**auth** actions require no destination — just `signingPath`, `actionType`, and `hash`.

**transfer** actions require a destination that is an internal address, subject
to the tier rules above.

**withdrawal** actions require a destination that is either an internal address
or is present in the external whitelist / drain address.

### External whitelist and drain address

**External whitelist** — a list of EVM (`0x...`) or Cosmos bech32 addresses
outside the mnemonic's HD tree (e.g. a second armory tier, a hot withdrawal
wallet). Any whitelisted address may receive withdrawals from any signing index.
No entry cap.

**Drain address** — a single emergency recovery address (must be a multisig in
production). Whitelisted for withdrawal from any index. Leave empty to disable.

For production, edit `EXTERNAL_WHITELIST_DEFAULT` and `DRAIN_ADDRESS_DEFAULT`
directly in `src/policy.ts`. For testing, use env var overrides (see below).

---

## Setup

```
npm install
npm run init
npm start
```

`npm run init` does all first-time setup:
1. Generates a 32-byte `ARMORY_KEY` and writes it to `.env`
2. Generates a random BIP-39 mnemonic and stores it encrypted in `.keys/mnemonic.enc`

To import an existing mnemonic instead of generating one:
```
ARMORY_MNEMONIC="word1 word2 ... word12" npm run init
```

After `init`, the daemon can be started and restarted any number of times with
`npm start`. It reads what is on disk; it never writes.

To start over, delete the key directory and the env entry:
```
rm -rf .keys/
# remove ARMORY_KEY= line from .env
npm run init
```

---

## Key rotation (rekey)

Rotate `ARMORY_KEY` without changing the mnemonic or any derived addresses:

```
npm run init rekey   # via script alias, if configured
# or directly:
npx tsx src/index.ts rekey
```

The daemon must not be running when `rekey` is called. Rekey:
1. Decrypts `mnemonic.enc` with the current `ARMORY_KEY`
2. Re-encrypts it with a newly generated key
3. Updates `ARMORY_KEY` in `.env`
4. Prints the new key to stdout

After rekeying, restart the daemon. The new key is loaded from `.env`
automatically (or pass it via `ARMORY_KEY` directly).

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ARMORY_KEY` | yes | 32-byte hex encryption key. Generated by `init`. |
| `ARMORY_SOCKET_PATH` | no | Unix socket path. Default: `/tmp/armory.sock` |
| `ARMORY_LOG_LEVEL` | no | `debug` \| `info` \| `none`. Default: `info` |
| `ARMORY_POOL_SIZE` | no | Number of HD indices to pre-derive. Default: `10000` |
| `ARMORY_MNEMONIC` | dev/test | Import a specific phrase during `init` instead of generating. Also accepted by the daemon for test harness compatibility (when `mnemonic.enc` does not yet exist). |
| `ARMORY_EXTERNAL_WHITELIST` | dev/test | Comma-separated address list. Overrides `EXTERNAL_WHITELIST_DEFAULT` in `policy.ts`. |
| `ARMORY_DRAIN_ADDRESS` | dev/test | Single EVM address. Overrides `DRAIN_ADDRESS_DEFAULT` in `policy.ts`. |
| `ARMORY_NO_DOTENV` | test | Set to `1` to skip `.env` loading. Used by the test harness to prevent `.env` from contaminating test runs. |

---

## Wire protocol

The daemon listens on a Unix socket. All communication uses 4-byte big-endian
length-prefix framing:

```
[ uint32 BE: payload length ][ UTF-8 payload bytes ]
```

### Connection lifecycle

1. **Server → client**: a 32-byte random nonce (64 hex chars), framed
2. **Client → server**: a 65-byte secp256k1 signature (130 hex chars), framed.
   The client signs the nonce with the key at `m/44'/60'/0'/0/255` derived
   from the mnemonic. If the signature does not recover to the expected address,
   the connection is closed immediately.
3. **Normal command exchange** begins. The server never sends an acknowledgement
   for successful pairing — the first response the client receives is the reply
   to its first command.

The pairing handshake verifies that the caller holds the same mnemonic. If the
mnemonic failed to load (e.g. corrupted `mnemonic.enc`), the armory is in error
state and accepts any pairing signature — but will return `err mnemonic not loaded`
for all commands except `status`.

### Rate limiting

Sign commands (`sign ...`) are rate-limited to **10 per second per connection**.
Requests that exceed this are rejected with `err rate limit exceeded` without
being dispatched.

### Commands

All requests and responses are plain UTF-8, whitespace-delimited. Responses are
either `ok <payload>` or `err <message>`.

#### `status`

```
→  status
←  ok ready
←  err mnemonic not loaded   (if mnemonic.enc could not be decrypted)
```

#### `derive <path>`

Derive an address from the mnemonic at the given BIP-44 path. Coin type
determines the address format.

```
→  derive m/44'/60'/0'/0/0
←  ok 0xAbCd...1234

→  derive m/44'/118'/0'/0/0
←  ok cosmos1abc...xyz

←  err invalid command        (bad path, unsupported coin type)
```

Supported coin types: `60` (EVM, `0x...`) and `118` (Cosmos, `cosmos1...`).

#### `sign <path> <actionType> [<destination>] <hash>`

Sign a 32-byte hash. The response is a 65-byte secp256k1 signature as 130
lowercase hex chars (`r[32] || s[32] || v[1]`).

**Auth actions** (no destination):
```
→  sign m/44'/60'/0'/0/5 approveAgent <64-char-hash>
←  ok <130-char-hex-signature>
```

**Transfer and withdrawal actions** (with destination):
```
→  sign m/44'/60'/0'/0/5 usdSend 0xDestAddr... <64-char-hash>
←  ok <130-char-hex-signature>

→  sign m/44'/60'/0'/0/5 withdraw3 0xExternalAddr... <64-char-hash>
←  ok <130-char-hex-signature>
```

Destinations must be EVM (`0x` + 40 hex chars) or Cosmos bech32 (`cosmos1...`
or `dydx1...`). Hashes must be exactly 64 hex chars (32 bytes).

Error responses:
```
←  err invalid command       (bad path, bad hash format, bad destination format)
←  err sign request denied   (action type not whitelisted, policy violation)
←  err mnemonic not loaded   (armory in error state)
←  err rate limit exceeded   (>10 sign commands/sec on this connection)
```

---

## Security properties

- **Mnemonic never leaves the process.** Callers send hashes; they receive
  signatures. No key material is ever transmitted.
- **Destination policy is hardcoded.** Callers cannot override the whitelist
  or tier rules by sending different arguments. Policy is enforced by the
  armory, not by the caller.
- **Pairing handshake.** Every new connection must prove knowledge of the
  mnemonic by signing a fresh nonce. A compromised caller that doesn't know
  the mnemonic cannot connect.
- **Encryption at rest.** `mnemonic.enc` is encrypted with Argon2id + AES-256-CBC.
  The key (`ARMORY_KEY`) must be stored separately from the encrypted file.
- **Rate limiting.** Sign commands are capped at 10/sec per connection to limit
  the blast radius of a compromised caller.
- **Uniform error messages.** All policy rejections return the same string
  (`err sign request denied`) regardless of reason, preventing callers from
  probing policy boundaries.

---

## File layout

```
src/
  index.ts        Entry point — CLI dispatch (init, rekey) and daemon startup
  server.ts       Unix socket server — framing, pairing handshake, rate limiting
  mnemonic.ts     Mnemonic lifecycle — generate, import, encrypt, load, rekey
  derivation.ts   BIP-32/44 derivation — EVM and Cosmos address encoding
  signer.ts       Action whitelist, destination policy, hash signing
  policy.ts       External whitelist and drain address (edit for production)
  protocol.ts     Wire protocol helpers — parse commands, format responses
  encryption.ts   Argon2id + AES-256-CBC encrypt/decrypt
  logger.ts       Structured logger (respects ARMORY_LOG_LEVEL)

.keys/
  mnemonic.enc    Encrypted mnemonic — never commit or transmit

.env              ARMORY_KEY — never commit or transmit
```

---

## Tests

Run the interactive CLI to execute the test suite:

```
npm run cli
```

Select `r` → Tests → `a` to run all phases, or select a specific phase number.

| Phase | What it covers |
|-------|----------------|
| 1 — Foundation | init keygen, startup without key, mnemonic generate/import, framing, status |
| 2 — Derivation + Address Pool | EVM/Cosmos derivation, determinism, path validation, pool uniqueness |
| 3 — Signing + Destination Policy | Auth/transfer/withdrawal signing, tier rules, error uniformity, input validation |
| 4 — dYdX Support | All dYdX action types, EVM path signing, policy correctness |
| 5 — Hardening | Pairing handshake, pairing failure, rate limiting, rekey |

Test scenarios live in `cli/scenarios/`. The shared harness (`_harness.ts`)
handles process lifecycle, pairing, and the `ArmoryClient` IPC wrapper.

All test runs use `ARMORY_NO_DOTENV=1` to prevent the local `.env` from
affecting results.
