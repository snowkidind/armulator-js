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

The daemon owns a BIP-39 mnemonic, derives addresses from it, and signs
transactions on behalf of callers — while enforcing a hardcoded destination
policy that callers cannot override.

The mnemonic never leaves the process. Callers send the **unsigned artifact**
(an EVM transaction or a Hyperliquid action); armory **recomputes the signing
hash from those bytes**, **extracts the true recipient from the same bytes**,
checks the recipient against its policy, and returns the derived signer address
plus a secp256k1 signature. The caller never supplies the digest, so the policy
decision is bound to exactly what gets signed.

---

## Quickstart

Node.js ≥ 18 (the `argon2` dependency builds a native addon, so a C/C++ toolchain
must be present).

```
npm install
cp .env.example .env          # then set EXTERNAL_WHITELIST_ADDRESS_01 in .env
npm run init                  # generates the key + mnemonic, prints HOTSERV_PAIRING_KEY
npm start                     # starts the daemon on the Unix socket
```

`npm run init` is the one-time startup ceremony: it writes `ARMORY_KEY` to `.env`,
stores an encrypted BIP-39 mnemonic under `.keys/`, and prints the pairing key your
client signs the handshake nonce with. armory refuses to start until
`EXTERNAL_WHITELIST_ADDRESS_01` is set, so the `.env` step is mandatory. The full
walkthrough — whitelist rationale, pairing, key rotation, and reset — is in
[Setup](#setup).

---

## What armory is for

armory is **not** a Hyperliquid tool, but it **is action-aware**: to bind the
policy decision to the bytes it signs, it owns the EVM transaction decoder and the
Hyperliquid EIP-712 schemas. At its core it does exactly two things:

1. **Recomputes the signing hash in-device** from the unsigned artifact the caller
   hands over (an EVM tx, or an HL action), and signs *that* hash with a key
   derived from the mnemonic (secp256k1) — never a caller-supplied digest, and
2. **Gates where value may go** — it only signs for a known *action type*, and for
   anything that moves funds, only to a recipient **decoded from the signed bytes**
   that satisfies a hardcoded policy a wire caller cannot override.

The caller still builds the artifact; armory never talks to an exchange or
broadcasts. But armory does decode the artifact far enough to answer, provably,
the **"should I sign this, to this recipient?"** question.

### Where the "should I sign?" decision lives

| Concern | File | Functions |
|---------|------|-----------|
| Is this action type allowed? How is its hash recomputed and its recipient decoded? | [`src/actions.ts`](./src/actions.ts) | `getDescriptor()` / `getCategory()` (action registry: category + `recomputeHash` + `extractRecipient`) |
| Recompute + decode the artifact | [`src/evm/extract.ts`](./src/evm/extract.ts), [`src/hl/typedData.ts`](./src/hl/typedData.ts) | EVM tx hash/recipient; HL EIP-712 hashes |
| Is the extracted recipient permitted? | [`src/signer.ts`](./src/signer.ts) | `checkPolicy()` (destination + tier rules, over the extracted recipient) |
| Which external addresses may receive withdrawals? | [`src/policy.ts`](./src/policy.ts) | `getExternalWhitelist()`, `getDrainAddress()` |

`actions.ts` binds each action type to how its hash is recomputed and its recipient
decoded; `signer.ts` holds the policy rules; `policy.ts` holds the address data
those rules consult. If you read only these files you understand what armory will
and won't authorize.

### What the reference deployment authorizes: Hyperliquid

Out of the box, the action whitelist in `signer.ts` is populated for **Hyperliquid
trading**. The Hyperliquid-specific part is a group of action-type *strings* —
nothing more:

| Action type | Purpose |
|-------------|---------|
| `approveAgent` | Authorize an ephemeral agent (API) key |
| `userSetAbstraction` | Set self/agent abstraction mode |
| `deposit` | Move USDC from wallet to exchange margin |
| `usdSend` | USDC peer-to-peer on the HL L2 |
| `usdClassTransfer` | USDC perps↔spot within the signer's own account |
| `spotSend` | Spot token (HYPE, …) peer-to-peer on the HL L2 |
| `withdraw3` | Withdraw USDC / spot token from the HL L2 to an external L1 address |

The same whitelist also carries a **generic EVM** group (`transfer`, `evmWithdraw` —
any EVM chain) and a **dYdX / Cosmos** group (`registerAccount`, `MsgSend`, … — a
different signing model on a Cosmos chain). See the full
[Action whitelist](#action-whitelist) table below.

### Which chains does it support?

armory derives addresses for two coin types — **EVM** (`m/44'/60'`, `0x…`) and
**Cosmos** (`m/44'/118'`, `cosmos1…` / `dydx1…`) — and is not limited to Arbitrum.
Because it recomputes the signing hash and decodes the recipient itself, each
artifact kind needs an in-device decoder: **generic EVM transactions** (native +
ERC-20) and **Hyperliquid EIP-712 actions** are implemented today; the **Cosmos /
dYdX** decoder is scaffolded (`cosmos-msg`) and **fails closed** until it lands
(see the [action registry](#action-whitelist)). Arbitrum appears only because that
is where Hyperliquid settles L1 withdrawals in the reference deployment — a
property of the *caller's* transactions, not of armory.

### Adapting it to your platform

To authorize a different exchange or protocol you edit the two policy files above and
build your own payloads client-side. Step-by-step walkthrough:
[`docs/ADAPTING.md`](./docs/ADAPTING.md).

A minimal working client that pairs, derives, and signs lives in
[`examples/reference-client.ts`](./examples/reference-client.ts) — run it against a
dev daemon with `npm run example`.

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

Each action type is a descriptor in [`src/actions.ts`](./src/actions.ts) that binds
it to a *category*, an *artifact kind*, a `recomputeHash`, and an `extractRecipient`.
Any `actionType` not in the registry is rejected with `err sign request denied`.

| Action type | Category | Artifact | Binding status | Notes |
|-------------|----------|----------|----------------|-------|
| `approveAgent` | auth | hl-action | bound | Authorize an ephemeral agent key on Hyperliquid |
| `userSetAbstraction` | auth | hl-action | bound | Set self/agent abstraction mode on Hyperliquid |
| `usdClassTransfer` | internal | hl-action | bound | USDC perps↔spot within the signer's own account |
| `usdSend` | transfer | hl-action | bound | USDC peer-to-peer on HL L2 |
| `spotSend` | transfer | hl-action | bound | Spot token (HYPE, etc.) peer-to-peer on HL L2 |
| `withdraw3` | withdrawal | hl-action | bound | HL L2 → external L1 (USDC or any spot token) |
| `transfer` | transfer | evm-tx | bound | ERC-20 or native send to internal address |
| `evmWithdraw` | withdrawal | evm-tx | bound | ERC-20 or native send to external whitelist |
| `deposit` | auth | hl-action | bound | Phantom-agent `source:'c'` scheme (not user-action); recomputes the committed hotserv hash (see `src/hl/typedData.ts`) |
| `registerAccount` | auth | cosmos-msg | **fails closed** | dYdX agent registration — Cosmos decoder deferred |
| `transferOut` | transfer | cosmos-msg | **fails closed** | dYdX USDC transfer — Cosmos decoder deferred |
| `withdraw` | withdrawal | cosmos-msg | **fails closed** | dYdX withdraw — Cosmos decoder deferred |
| `AddAuthenticator` | auth | cosmos-msg | **fails closed** | Register permissioned trading key on dYdX |
| `RemoveAuthenticator` | auth | cosmos-msg | **fails closed** | Revoke permissioned trading key on dYdX |
| `MsgTransfer` | transfer | cosmos-msg | **fails closed** | Between accounts on dYdX |
| `MsgSend` | transfer | cosmos-msg | **fails closed** | Native token send on dYdX (gas distribution) |
| `MsgWithdrawFromSubaccount` | withdrawal | cosmos-msg | **fails closed** | dYdX subaccount withdrawal |

**Binding status** — *bound* actions recompute the hash and extract the recipient
in-device. *Fails closed* actions are registered (so callers see a consistent
category) but their recompute is not yet implemented, so any sign request for them
is refused rather than signed blindly. The Cosmos / dYdX decoder is not implemented yet.

**auth** actions carry no external recipient. armory still recomputes the hash from
the claimed action's schema, so a fund-moving artifact submitted under an auth
action type fails to recompute and is denied (actionType-spoof closed).

**internal** actions also carry no external recipient: the funds move within the
signer's own account (e.g. perps↔spot ledger transfer), recovered from the
signature. Nothing external for policy to validate.

**transfer** actions require the recipient decoded from the signed bytes to be an
internal address, subject to the tier rules above.

**withdrawal** actions require the decoded recipient to be either an internal
address or present in the external whitelist / drain address.

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

#### `sign <signingPath> <actionType> <base64url(requestJSON)>`

The caller sends the **unsigned artifact**, never a digest. armory recomputes the
signing hash from the artifact, extracts the true recipient from those same bytes,
checks the recipient against policy, signs the recomputed hash, and returns the
derived signer address **and** the signature.

`base64url(requestJSON)` is a single whitespace-free base64url token (no padding) of:

```jsonc
{
  "artifact":
      { "kind": "evm-tx",    "unsignedTx": "0x..." }        // generic EVM (evmWithdraw / transfer)
    | { "kind": "hl-action", "action": { ...wire JSON... } }, // HL L2 EIP-712 actions
  "destination": "0x..." | "cosmos1..." | null              // HINT only — cross-checked, never trusted
}
```

Example (HL withdrawal):
```
→  sign m/44'/60'/0'/0/100 withdraw3 <base64url({"artifact":{"kind":"hl-action","action":{...}}})>
←  ok 0xSignerAddr... <130-char-hex-signature>
```

The response is `ok <derivedAddress> <signature130hex>`, where `<derivedAddress>` is
the address at `<signingPath>`. The **caller MUST assert** it equals the expected
signer before broadcast/submit (money-path key-match guard). The signature is a
65-byte secp256k1 signature as 130 lowercase hex chars (`r[32] || s[32] || v[1]`).

`destination` is an optional HINT: when non-null it must equal the recipient armory
decodes from the bytes, or the request is denied (defense in depth). It can never
*authorize* a recipient — only the decoded bytes can.

Error responses:
```
←  err invalid command       (malformed path / base64 / JSON / artifact shape)
←  err sign request denied   (unknown action type, undecodable artifact, policy violation)
←  err mnemonic not loaded   (armory in error state)
←  err rate limit exceeded   (>10 sign commands/sec on this connection)
```

---

## Security properties

These are the properties the emulator enforces **against a caller on the socket** —
i.e. within the emulator's trust boundary. They are not hardware guarantees; read
[Security model & limitations](#security-model--limitations) for where they stop.

- **Mnemonic never leaves the process.** Callers send unsigned artifacts; they
  receive a signature. No key material is ever transmitted over the socket.
- **The signed hash is recomputed in-device and bound to the policy decision.**
  armory recomputes the signing hash from the artifact (EVM `unsignedHash` /
  HL EIP-712) and decodes the true recipient from those same bytes — the native
  `to`, the ERC-20 `transfer` recipient in calldata, or the HL action's
  destination field. The caller cannot supply a divergent digest, and the policy
  is checked against the recipient of exactly what gets signed. This closes the
  issue-#5 whitelist bypass (a caller asserting a whitelisted destination while
  handing over a hash paying an attacker) and actionType-spoofing (a fund-moving
  artifact submitted under an auth action fails to recompute → denied). Any
  artifact armory cannot decode **fails closed**.
- **Destination policy is enforced by the armory, not the caller.** A wire
  caller cannot override the whitelist or tier rules by sending different
  arguments, and the caller-supplied `destination` is a cross-check hint only,
  never authoritative. (Note: the *operator* can change policy via env vars at
  restart — see limitation 2.)
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

10. **The session model is multi-peer with no identity.** The server serves multiple
    concurrent paired connections; each pairs independently with equal authority, a
    second peer neither evicts nor is detected by the first, and pairing authenticates
    possession of the pairing key, not the identity of the connecting process.
    (Documentation only; enforcing single-session / peer-cred / `0600` is a separate
    decision.)

Protocol-level note, true of the emulator *and* a real device: the logger emits only
the command *name* at runtime, never arguments, artifacts, hashes, or the mnemonic;
the only cleartext key exposure is at `init`/`rekey` (points 4, 8).

> **Binding note.** The policy is evaluated against the signed bytes, never against
> caller-supplied strings. armory recomputes the signing hash from the artifact and
> decodes the recipient from those same bytes, so the `actionType`/`destination` a
> caller asserts can only ever *fail* the check, not smuggle a different payload past
> it. See [Security properties](#security-properties).

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
  index.ts        Entry point — CLI dispatch (init, rekey), daemon startup, sign dispatch
  server.ts       Unix socket server — framing, pairing handshake, rate limiting
  mnemonic.ts     Mnemonic lifecycle — generate, import, encrypt, load, rekey
  derivation.ts   BIP-32/44 derivation — EVM and Cosmos address encoding
  actions.ts      Action descriptor registry — category + recomputeHash + extractRecipient
  evm/extract.ts  EVM artifact: recompute unsignedHash + decode recipient (native/ERC-20)
  hl/typedData.ts Hyperliquid EIP-712 schemas (local copy) + hash recompute
  signer.ts       Destination policy over the extracted recipient, hash signing
  policy.ts       External whitelist and drain address (edit for production)
  protocol.ts     Wire protocol helpers — parse commands, format responses
  encryption.ts   Argon2id + AES-256-CBC encrypt/decrypt
  logger.ts       Structured logger (respects ARMORY_LOG_LEVEL)

.keys/
  mnemonic.enc    Encrypted mnemonic — never commit or transmit

.env              ARMORY_KEY — never commit or transmit

examples/
  reference-client.ts   Minimal standalone client — pair, derive, sign (npm run example)

docs/
  ADAPTING.md           How to retarget the action whitelist and policy to your platform
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
affecting results; the harness injects a bogus `EXTERNAL_WHITELIST_ADDRESS_01`
(which `policy.ts` requires at load) so the daemon starts hermetically. The
injected address is logged on each run so it is never mistaken for a real one.

---

## License

Licensed under the **PolyForm Noncommercial License 1.0.0** — any noncommercial
purpose is permitted (personal use, research, education, and noncommercial
organizations). Commercial use requires a separate license from the copyright
holder. See [`LICENSE.md`](./LICENSE.md) for the full terms.
