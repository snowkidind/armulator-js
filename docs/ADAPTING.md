# Adapting armory to your platform

armory ships configured to authorize **Hyperliquid** trading, but nothing about
the daemon is Hyperliquid-specific beyond a list of allowed action names. This
guide shows how to retarget it.

Before you start, hold onto the one idea that makes everything else simple:

> **armory signs hashes and gates destinations. It does not build transactions.**
> Your client builds the payload for your exchange/chain, hashes it, and asks
> armory to sign. armory only decides *"should I sign this?"*.

So "supporting a new platform" is two jobs:

1. **In armory** — tell it which action names and destinations are permitted
   (`src/signer.ts` + `src/policy.ts`).
2. **In your client** — build the payloads and 32-byte hashes for that platform,
   and send them over the socket. armory never does this part.

---

## The two files you edit

### 1. `src/signer.ts` — the rules

Two things live here:

**The action whitelist** (`ACTION_WHITELIST`). A `Map` from an action-type string
to one of four categories:

| Category | Needs a destination? | Policy applied |
|----------|----------------------|----------------|
| `auth` | no | none — signs an authorization that moves no funds |
| `internal` | no | none — funds move within the signer's own account (target recovered from the signature) |
| `transfer` | yes | destination must be an **internal pool** address, subject to the tier rules |
| `withdrawal` | yes | destination must be an **internal pool** address **or** on the external whitelist / drain address |

Anything not in the map is rejected with `err sign request denied`.

**The destination policy** (`checkPolicy()`). This is the gate that runs for every
`transfer`/`withdrawal`. It enforces the index-tier rules (staging indices 0–49 may
only push to high-value indices 50–99; index 50+ may send anywhere internal) and the
external-whitelist check for withdrawals.

### 2. `src/policy.ts` — the address data

`checkPolicy()` asks this file *which external addresses are allowed to receive
withdrawals*. For production you edit `EXTERNAL_WHITELIST_DEFAULT` and
`DRAIN_ADDRESS_DEFAULT` directly; for dev/test you override them with the
`ARMORY_EXTERNAL_WHITELIST` / `ARMORY_DRAIN_ADDRESS` env vars.

---

## Walkthrough: add a new action type

Say your platform needs a "stake" authorization — it moves no funds, just signs a
staking authorization. That's an `auth` action. Add one line to the map in
`src/signer.ts`:

```ts
const ACTION_WHITELIST = new Map<string, ActionCategory>([
  // ...existing entries...
  ['stake', 'auth'],   // your new action
])
```

Your client then asks for it exactly like any other auth action — a signing path,
the action name, and the 32-byte hash of whatever payload your platform signs:

```
sign m/44'/60'/0'/0/5 stake <64-hex-char-hash>
```

That's the whole change. No new endpoint, no protocol change.

- If the new action **moves funds to another of your own addresses**, make it a
  `transfer` instead and pass a destination; `checkPolicy()` will require the
  destination to be in the internal pool under the tier rules.
- If it **withdraws to an outside address**, make it a `withdrawal` and add that
  address to the whitelist in `policy.ts` (or via `ARMORY_EXTERNAL_WHITELIST`).

## Walkthrough: target a different chain

armory already derives addresses on two coin types — EVM (`m/44'/60'`) and Cosmos
(`m/44'/118'`) — and signs a raw secp256k1 hash, so **most EVM and Cosmos chains
need no derivation changes at all.** You only touch `src/derivation.ts` if your
chain uses a different coin type or a non-secp256k1 address encoding.

For a typical new EVM chain the only armory-side work is deciding which action
names and destinations to allow (the two files above). Everything chain-specific —
RPC, nonces, gas, the exact bytes that get hashed — is your client's job.

---

## What you must NOT change to "make it work"

These exist on purpose; weakening them defeats the point of the daemon.

- **Don't let the caller choose the whitelist.** The policy must be owned by
  armory, not passed in on the wire. That is the one guarantee a signer provides.
- **Don't add a "skip policy" action or a dev bypass.** There is deliberately no
  dev/prod branch in the signing path — see the README security notes.
- **Don't make rejections descriptive.** Every policy denial returns the same
  `err sign request denied` so a caller can't probe the policy boundary. Keep it
  uniform.

---

## Testing your changes

The CLI test suite (`npm run cli` → Tests) covers the whitelist, tier rules, and
policy. Add a scenario under `cli/scenarios/` for any new action type, following
the existing Phase 3 signing scenarios. For a quick manual round-trip against a
running daemon, use [`examples/reference-client.ts`](../examples/reference-client.ts)
(`npm run example`) and add your new command to it.
