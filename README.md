# armory (armulator-js)

A JavaScript emulator of the [USB Armory](https://github.com/usbarmory/usbarmory)
hardware security module. It implements the same IPC protocol and security
model that the physical device exposes, allowing the rest of the system to be
developed and tested without hardware present. When a USB Armory unit is
available, this daemon is replaced by the device; no changes are required in
callers.

> ⚠️ **This is an emulator for development and testing — not a hardware security
> module.** It reproduces the *interface* of the device, not its hardware
> security guarantees. Do not rely on it to protect real funds or real key
> material. If you need actual security, use a real USB Armory (or equivalent
> HSM). See [Security model & limitations](#security-model--limitations).

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

Both sequences run from index 0 to `ARMORY_POOL_SIZE - 1` (default 125).
These are the **internal addresses**. Only transfers between internal addresses
are permitted. Transfers out of the pool require an external whitelist entry.
The pool grows on demand: a `derive`/`sign` request for an index beyond the
current pool expands it to cover that index.

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
| `userSetAbstraction` | auth | Set self/agent abstraction mode on Hyperliquid |
| `deposit` | auth | Move USDC from wallet to exchange margin |
| `usdSend` | transfer | USDC peer-to-peer on HL L2 |
| `usdClassTransfer` | internal | USDC perps↔spot within the signer's own account |
| `spotSend` | transfer | Spot token (HYPE, etc.) peer-to-peer on HL L2 |
| `withdraw3` | withdrawal | HL L2 → external L1 (USDC or any spot token) |
| `transfer` | transfer | ERC-20 or native send to internal address |
| `evmWithdraw` | withdrawal | ERC-20 or native send to external whitelist |
| `registerAccount` | auth | dYdX agent registration (ETH personal_sign) |
| `transferOut` | transfer | dYdX USDC transfer to another account |
| `withdraw` | withdrawal | dYdX withdraw to own address |
| `AddAuthenticator` | auth | Register permissioned trading key on dYdX |
| `RemoveAuthenticator` | auth | Revoke permissioned trading key on dYdX |
| `MsgTransfer` | transfer | Between accounts on dYdX |
| `MsgSend` | transfer | Native token send on dYdX (gas distribution) |
| `MsgWithdrawFromSubaccount` | withdrawal | dYdX subaccount withdrawal |

**auth** actions require no destination — just `signingPath`, `actionType`, and `hash`.

**internal** actions also take no destination: the funds move within the
signer's own account (e.g. perps↔spot ledger transfer), so the routing target
is the signer itself, recovered from the signature. Nothing for policy to validate.

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

**Prerequisites:** Node.js ≥ 18. The `argon2` dependency builds a native addon,
so a working C/C++ toolchain is needed if no prebuilt binary is available for
your platform (`build-essential` / Xcode Command Line Tools / MSVC build tools).

```
npm install
cp .env.example .env          # then set EXTERNAL_WHITELIST_ADDRESS_01 in .env
npm run init
npm start
```

The `.env` step is mandatory **by design**: armory will not run without a declared
external withdrawal whitelist. `src/policy.ts` requires `EXTERNAL_WHITELIST_ADDRESS_01`
and refuses to load (so both `init` and the daemon refuse to start) until you set it —
forcing an explicit decision about where funds may be withdrawn rather than defaulting
to something permissive. For emulator/dev use any valid EVM address is fine (see
`.env.example`); for real use, set your actual withdrawal address.

`npm run init` does all first-time setup:
1. Generates a 32-byte `ARMORY_KEY` and writes it to `.env`
2. Generates a random BIP-39 mnemonic and stores it encrypted in `.keys/mnemonic.enc`
3. Prints a `HOTSERV_PAIRING_KEY` — see below.

### Connecting your software

armory is only useful with a client connecting to it. Every connection must
complete the [pairing handshake](#connection-lifecycle): the client proves it
holds the armory's mnemonic by signing the server's nonce with the key at
`m/44'/60'/0'/0/255`. `init` derives that key and prints its **private key** so
you can hand it to your client:

```
HOTSERV_PAIRING_KEY=0x...
```

Place this value in your connecting application's configuration. The name
`HOTSERV_PAIRING_KEY` reflects the reference client (`hotserv`); if you are
wiring up your own software, read it under whatever name that software expects —
it is just "the private key my client signs the pairing nonce with." Your client
then: opens the Unix socket, reads the framed 32-byte nonce, signs it with this
key, and sends back the framed 65-byte signature. See
[Wire protocol → Connection lifecycle](#connection-lifecycle) for the exact bytes.

> This key is derived from the mnemonic and is printed in cleartext at `init`.
> Treat it as a secret and keep it out of version control. See
> [Security model & limitations](#security-model--limitations).

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
npm run rekey
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
| `EXTERNAL_WHITELIST_ADDRESS_01` | yes | External withdrawal address, appended to the `policy.ts` defaults. **Required by design** — `policy.ts` refuses to load until it is set, so armory never starts without a declared withdrawal whitelist. |
| `ARMORY_SOCKET_PATH` | no | Unix socket path. Default: `/tmp/armory.sock` |
| `ARMORY_LOG_LEVEL` | no | `debug` \| `info` \| `none`. Default: `info` |
| `ARMORY_POOL_SIZE` | no | Number of HD indices to pre-derive. Default: `125` |
| `ARMORY_KEYS_DIR` | no | Directory holding `mnemonic.enc`. Default: `.keys/` next to the package root. |
| `ARMORY_ENV_PATH` | no | Path to the `.env` file that `init`/`rekey` write to. Default: `.env` next to the package root. |
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

#### `noop`

Liveness primitive. Exercises pairing, framing, and dispatch without doing any
cryptographic work — used by readiness/health probes.

```
→  noop
←  ok alive
←  err mnemonic not loaded   (if the armory is in error state)
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

These are the properties the emulator enforces **against a caller on the socket** —
i.e. within the emulator's trust boundary. They are not hardware guarantees; read
[Security model & limitations](#security-model--limitations) for where they stop.

- **Mnemonic never leaves the process.** Callers send hashes; they receive
  signatures. No key material is ever transmitted over the socket.
- **Destination policy is enforced by the armory, not the caller.** A wire
  caller cannot override the whitelist or tier rules by sending different
  arguments. (Note: the *operator* can change policy via env vars at restart —
  see limitation 2.)
- **Pairing handshake.** Every new connection must prove knowledge of the
  mnemonic by signing a fresh nonce. A caller that doesn't hold the
  mnemonic-derived pairing key cannot connect.
- **Encryption at rest.** `mnemonic.enc` is encrypted with Argon2id + AES-256-CBC.
  The key (`ARMORY_KEY`) *should* be stored separately from the encrypted file —
  but `init` writes both to the same host (see limitation 1).
- **Rate limiting.** Sign commands are capped at 10/sec per connection to limit
  the blast radius of a runaway caller (per-connection, in-memory — see limitation 6).
- **Uniform error messages.** All policy rejections return the same string
  (`err sign request denied`) regardless of reason, preventing callers from
  probing policy boundaries.

---

## Security model & limitations

`armory` is a **software emulator**. It speaks the same IPC protocol a real USB
Armory would, so the rest of the system can be built and tested without hardware.
It is **not** a security boundary. The limitations below are inherent to running
an HSM's job as an ordinary Unix process — they are not bugs to be fixed in the
emulator. All points were verified against the source.

1. **The encryption key lives on the same disk as the data it encrypts.**
   `init` writes `ARMORY_KEY` to `.env` and the encrypted mnemonic to
   `.keys/mnemonic.enc` under the same package root, and the daemon reads the
   key back from that `.env`. Anyone who can read the project directory gets both
   halves and can decrypt the mnemonic offline. *Real hardware:* the secret never
   leaves the secure element; copying the disk yields nothing.

2. **Destination policy is runtime-overridable, not burned into firmware.**
   `src/policy.ts` returns env-var values when present (`ARMORY_EXTERNAL_WHITELIST`,
   `ARMORY_DRAIN_ADDRESS`), and even the "default" whitelist requires
   `EXTERNAL_WHITELIST_ADDRESS_01` from the environment at load. There is no
   dev/prod gate. Anyone who can set an env var and restart the process can add a
   withdrawal destination or drain address. *Real hardware:* these are compile-time
   constants in signed firmware; changing them means reflashing the device.

3. **The mnemonic is decrypted into ordinary process memory.** The plaintext
   BIP-39 phrase is held as a JS string for the life of the process and reused on
   every derivation/sign (`src/index.ts`, `src/signer.ts`, `src/derivation.ts`),
   with no locking or zeroing. Swap, core dumps, `/proc/<pid>/mem`, a debugger, or
   a heap snapshot can expose it. *Real hardware:* keys never exist outside the
   secure element; signing happens on-chip.

4. **Pairing is a shared secret derived from the mnemonic — and printed to stdout.**
   The handshake only proves the client can sign a nonce with the key at
   `m/44'/60'/0'/0/255`, which is derived from the same mnemonic the daemon holds.
   `init` prints that key's **private key** as `HOTSERV_PAIRING_KEY=` for the
   operator to copy. It is caller authentication for dev convenience, not a
   hardware attestation. *Real hardware:* attestation uses an on-chip key that is
   never exported and never appears on stdout.

5. **No hardware isolation, tamper resistance, secure boot, hardware RNG, or air-gap.**
   It is a `net.createServer` Unix-socket daemon at `/tmp/armory.sock`; socket
   reachability is whatever the host umask allows. Entropy comes from the software
   CSPRNG `crypto.randomBytes`, not a hardware RNG. Any local process that can
   reach the socket and holds the pairing key can request signatures.

6. **Rate limiting is per-connection and in-memory.** The 10 signs/sec cap is a
   sliding window held per socket (`src/server.ts`); it resets on reconnect or
   restart, and `N` connections yield `N × 10`/sec. Only `sign` is limited —
   `derive` is not. It bounds an accidental loop, not an attacker.

7. **Error-state fallback accepts any pairing signature.** If `mnemonic.enc`
   cannot be decrypted, the daemon does not exit — it runs with `mnemonic = null`
   and `verifyPairing = () => true`, accepting any pairing attempt. It is contained
   (every command then returns `err mnemonic not loaded`, so nothing can be signed),
   but a degraded armory drops its one authentication check.

8. **Secrets sit at rest in a plaintext dotfile; `rekey` prints the new key.**
   `ARMORY_KEY` is a cleartext line in `.env`, and `rekey` both writes and prints
   the new key to stdout by design. `.env` and `.keys/` are gitignored, so the
   risk is host access, not accidental commit.

9. **At-rest encryption is unauthenticated.** `src/encryption.ts` uses AES-256-**CBC**
   with no MAC/auth tag, so `mnemonic.enc` has no integrity check — tampering is
   only caught incidentally when the decrypted bytes fail BIP-39 validation. Adequate
   to obfuscate a dev secret; not tamper-evident storage.

Two protocol-level notes, true of the emulator *and* a real device: policy is
evaluated against the caller-supplied `actionType`/`destination` **strings**, which
are not cryptographically bound to the 32-byte hash being signed — a caller can
assert a permitted action while submitting a hash committing to something else.
And at runtime the logger emits only the command *name*, never arguments, hashes,
or the mnemonic; the only cleartext key exposure is at `init`/`rekey` (points 4, 8).

> **This is an emulator for development and testing. It is not a hardware security
> module and must not be relied on to protect real funds or real key material.** It
> runs the mnemonic in ordinary process memory, keeps its encryption key on the same
> disk as the data it encrypts, enforces a policy any local operator can override
> with an environment variable, and authenticates callers with a secret derived from
> (and printed alongside) the mnemonic itself. If you need actual security, use a
> real USB Armory (or an equivalent HSM) — do not deploy this emulator against real
> value.

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

---

## License

Licensed under the **PolyForm Noncommercial License 1.0.0** — any noncommercial
purpose is permitted (personal use, research, education, and noncommercial
organizations). Commercial use requires a separate license from the copyright
holder. See [`LICENSE.md`](./LICENSE.md) for the full terms.
