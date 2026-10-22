# Adapting armory to your platform

armory ships configured to authorize **Hyperliquid** trading, but nothing about
the daemon is Hyperliquid-specific beyond the set of actions it knows how to
recompute and gate. This guide shows how to retarget it.

Before you start, hold onto the one idea that makes everything else safe:

> **armory decides "should I sign this?" — and to decide safely it recomputes the
> signing hash itself and reads the true recipient out of the same bytes it will
> sign.** Your client builds the *unsigned* action (an EVM transaction, or your
> exchange's typed action) and sends that artifact over the socket. armory never
> trusts a caller-supplied hash or a caller-asserted destination — it derives both
> from the artifact. That binding is the whole point of the device.

So "supporting a new platform" is two jobs:

1. **In armory** — register the action: its category, how to recompute its hash
   from the artifact, and how to extract its recipient (`src/actions.ts`), plus the
   destination policy (`src/signer.ts` + `src/policy.ts`).
2. **In your client** — build the *unsigned artifact* for that platform and send it
   over the socket. armory recomputes the hash and signs. Your client never hashes.

---

## The files you edit

### 1. `src/actions.ts` — the action registry

One descriptor per action type, keyed by its wire name:

```ts
register('withdraw3', 'withdrawal', hlWithRecipient(hl.hashWithdraw3))
```

A descriptor is `{ category, artifactKind, recomputeHash(artifact), extractRecipient(artifact) }`:

- **`category`** — one of four (table below). Decides which policy runs.
- **`artifactKind`** — the artifact this action arrives as: `evm-tx` (an unsigned
  on-chain tx), `hl-action` (a Hyperliquid typed action), or `cosmos-msg`.
- **`recomputeHash(artifact)`** — recomputes the 32-byte digest armory will sign,
  from the artifact. For `evm-tx` it's `Transaction.from(unsignedTx).unsignedHash`;
  for `hl-action` it's the EIP-712 hash of the action's typed-data schema. The
  caller cannot hand armory a divergent digest — bytes inspected == bytes signed.
- **`extractRecipient(artifact)`** — pulls the true recipient out of those same
  bytes (native `to` / ERC-20 calldata recipient / the `destination` field of a
  typed action), or `{ kind: 'none' }` for actions that move no funds. **Fails
  closed** on any shape it does not recognize.

The helpers `hlNoRecipient`, `hlWithRecipient`, `evmTx`, and `cosmosScaffold`
build these descriptors for the common cases. Anything not in the registry is
rejected with `err sign request denied`.

| Category | Recipient | Policy applied |
|----------|-----------|----------------|
| `auth` | none (extractor returns `none`) | none — signs an authorization that moves no funds |
| `internal` | none | none — funds move within the signer's own account (recovered from the signature), not to an external party |
| `transfer` | extracted | recipient must be an **internal pool** address, subject to the tier rules |
| `withdrawal` | extracted | recipient must be an **internal pool** address **or** on the external whitelist / drain address |

The `auth`/`internal` "recipient must be none" check also closes action-type
spoofing: because armory recomputes the hash from the claimed action type, a caller
cannot label a fund-moving payload as an `auth` action to skip the destination gate.

### 2. `src/signer.ts` — the destination policy

`checkPolicy()` runs for every `transfer`/`withdrawal`, **against the recipient
armory extracted** (never a caller-supplied string). It enforces the index-tier
rules (staging indices 0–49 may only push to high-value indices 50–99; index 50+
may send anywhere internal) and the external-whitelist check for withdrawals.

### 3. `src/policy.ts` — the address data

`checkPolicy()` asks this file *which external addresses may receive withdrawals*.
For production you edit `EXTERNAL_WHITELIST_DEFAULT` and `DRAIN_ADDRESS_DEFAULT`
directly; for dev/test you override them with the `ARMORY_EXTERNAL_WHITELIST` /
`ARMORY_DRAIN_ADDRESS` env vars.

---

## The sign wire

```
sign <signingPath> <actionType> <base64url(requestJSON)>
```

`requestJSON` is a single whitespace-free base64url token (no padding) of:

```jsonc
{
  "artifact":
      { "kind": "evm-tx",    "unsignedTx": "0x..." }        // unsigned on-chain EVM tx
    | { "kind": "hl-action", "action": { ...typed action... } },
  "destination": "0x..." | null    // HINT only — cross-checked against the extracted recipient, never trusted
}
```

The reply is `ok <derivedAddress> <signature130hex>`. **Your client MUST assert
`<derivedAddress>` equals the signer address it expected before it broadcasts or
submits anything** (the money-path key-match guard). Policy/undecodable/unknown
failures all return the uniform `err sign request denied`.

---

## Walkthrough: add a new action type

Say your platform needs a "stake" authorization — it moves no funds, just signs a
staking authorization. That's an `auth` action. Add a descriptor in `src/actions.ts`:

```ts
// hashStake(action) recomputes the EIP-712 (or chain-native) digest from the action.
register('stake', 'auth', hlNoRecipient(hashStake))
```

Your client builds the unsigned action and sends it as the artifact — it never
computes the hash:

```
sign m/44'/60'/0'/0/5 stake <base64url({"artifact":{"kind":"hl-action","action":{...}}})>
```

That's the whole change. No new endpoint, no protocol change.

- If the new action **moves funds to another of your own addresses**, register it
  as a `transfer` with an `extractRecipient` that reads the recipient from the
  artifact (`hlWithRecipient(...)`); `checkPolicy()` then requires that recipient
  to be in the internal pool under the tier rules.
- If it **withdraws to an outside address**, register it as a `withdrawal` and add
  that address to the whitelist in `policy.ts` (or via `ARMORY_EXTERNAL_WHITELIST`).

## Walkthrough: target a different chain

armory already derives addresses on two coin types — EVM (`m/44'/60'`) and Cosmos
(`m/44'/118'`) — and signs a raw secp256k1 hash, so **most EVM and Cosmos chains
need no derivation changes at all.** You only touch `src/derivation.ts` if your
chain uses a different coin type or a non-secp256k1 address encoding.

For a typical new EVM chain the only armory-side work is registering the actions
you allow and recomputing their hashes from the unsigned tx — the `evmTx`
descriptor already recomputes `unsignedHash` and extracts the native/ERC-20
recipient for you. Everything else chain-specific — RPC, nonces, gas, building the
unsigned tx — is your client's job.

---

## What you must NOT change to "make it work"

These exist on purpose; weakening them defeats the point of the daemon.

- **Don't let the caller supply the hash or the authoritative destination.** armory
  recomputes the hash from the artifact and extracts the recipient from the same
  bytes; the wire `destination` is a cross-check hint only. This binding is the one
  guarantee a signer provides — do not add a path that signs a caller-provided digest.
- **Don't let the caller choose the whitelist.** The policy is owned by armory, not
  passed in on the wire.
- **Don't add a "skip policy" action or a dev bypass.** There is deliberately no
  dev/prod branch in the signing path — see the README security notes.
- **Don't make rejections descriptive.** Every denial returns the same
  `err sign request denied` so a caller can't probe the policy boundary.
- **Don't fail open.** An artifact whose recipient or hash can't be decoded is
  rejected, never signed on a guess.

---

## Testing your changes

The CLI test suite (`npm run cli` → Tests) covers the whitelist, tier rules, and
the destination-binding scenarios (`cli/scenarios/3.9`, `3.10` — a whitelisted
`destination` hint paired with an artifact paying a non-whitelisted address is
denied). Add a scenario under `cli/scenarios/` for any new action type: a positive
path (the recomputed hash recovers to the expected signer) and a binding-negative
path (hint ≠ extracted recipient → denied). For a quick manual round-trip against a
running daemon, use [`examples/reference-client.ts`](../examples/reference-client.ts)
(`npm run example`) and add your new command to it.
