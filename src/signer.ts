/**
 * Destination policy and hash signing.
 *
 * The action whitelist and the per-action recompute/extract descriptors now live
 * in `src/actions.ts`. This module owns the destination policy decision — now
 * evaluated against the recipient EXTRACTED from the signed bytes (not a
 * caller-supplied string) — and the raw hash signing.
 *
 * Action categories:
 *   auth       — no external recipient (approveAgent, AddAuthenticator, etc.)
 *   internal   — no external recipient; funds move within the signer's own
 *                account (e.g. HL usdClassTransfer between perps↔spot ledgers).
 *   transfer   — recipient must be in the internal pool; index tier applies
 *   withdrawal — recipient must be in the external whitelist / drain, or internal
 *
 * Transfer tier rules:
 *   Signing index 0–49  → recipient must be in indices 50–99 (staging door)
 *   Signing index 50+   → recipient may be anywhere in internal pool
 *
 * Withdrawal rules (any signing index):
 *   Recipient must be an internal pool address, or in the external whitelist
 *   (ARMORY_EXTERNAL_WHITELIST / ARMORY_DRAIN_ADDRESS).
 */
import { HDNodeWallet }                      from 'ethers'
import { pathIndex }                         from './derivation.js'
import { getExternalWhitelist, getDrainAddress } from './policy.js'
import type { AddressPool }                  from './derivation.js'
import type { ActionCategory, Recipient }   from './actions.js'

// ── Input validation ──────────────────────────────────────────────────────────

const HASH_RE   = /^[0-9a-fA-F]{64}$/
const EVM_RE    = /^0x[0-9a-fA-F]{40}$/i
const COSMOS_RE = /^(cosmos1|dydx1)[a-z0-9]{38,}$/

export function isValidHash(hash: string): boolean {
  return HASH_RE.test(hash)
}

export function isValidDestination(dest: string): boolean {
  return EVM_RE.test(dest) || COSMOS_RE.test(dest)
}

// ── Destination policy ────────────────────────────────────────────────────────

function getInternalIndex(dest: string, pool: AddressPool): number | null {
  const evmIdx = pool.evmIndexMap.get(dest.toLowerCase())
  if (evmIdx !== undefined) return evmIdx
  const cosmosIdx = pool.cosmosIndexMap.get(dest)
  if (cosmosIdx !== undefined) return cosmosIdx
  return null
}

function isExternalWhitelisted(dest: string): boolean {
  // EVM addresses are case-insensitive (compare lowercase).
  // Cosmos bech32 addresses are already lowercase by spec.
  const lower = dest.toLowerCase()
  const drain  = getDrainAddress()
  if (drain && lower === drain.toLowerCase()) return true
  return getExternalWhitelist().some(w => w.toLowerCase() === lower)
}

/**
 * Check the destination policy for a sign request, against the recipient
 * EXTRACTED from the bytes being signed. `destHint` is the caller-supplied
 * `requestJSON.destination` — a cross-check only, never authoritative: when
 * non-null it must equal the extracted recipient (defense in depth).
 *
 * Returns true if the request is permitted, false if it must be denied.
 */
export function checkPolicy(
  signingPath: string,
  category:    ActionCategory,
  recipient:   Recipient,
  destHint:    string | null,
  pool:        AddressPool,
): boolean {
  // auth / internal: the bytes must move no funds to an external recipient.
  // This also closes actionType-spoofing — the hash was recomputed from the
  // claimed action's schema, so a fund-move artifact cannot masquerade as auth.
  if (category === 'auth' || category === 'internal') {
    return recipient.kind === 'none'
  }

  // transfer / withdrawal: there must be a decoded external recipient.
  if (recipient.kind !== 'transfer') return false
  const dest = recipient.recipient
  if (!isValidDestination(dest)) return false

  // Defense-in-depth: a non-null caller hint must agree with the extracted bytes.
  if (destHint !== null) {
    if (!isValidDestination(destHint)) return false
    if (destHint.toLowerCase() !== dest.toLowerCase()) return false
  }

  const signingIdx = pathIndex(signingPath)

  if (category === 'transfer') {
    const destIdx = getInternalIndex(dest, pool)
    if (destIdx === null) return false           // not an internal address
    if (signingIdx <= 49) return destIdx >= 50 && destIdx <= 99
    return true                                  // 50+: any internal address
  }

  // withdrawal: internal pool OR external whitelist
  // (e.g. withdraw3 back to own on-chain address, or evmWithdraw to second armory)
  if (getInternalIndex(dest, pool) !== null) return true
  return isExternalWhitelisted(dest)
}

// ── Signing ───────────────────────────────────────────────────────────────────

/**
 * Sign a 32-byte hash with the key derived from the given BIP-44 path.
 * Returns a 65-byte signature as 130 lowercase hex chars: r(32) || s(32) || v(1).
 */
export function signHash(mnemonic: string, path: string, hashHex: string): string {
  const wallet = HDNodeWallet.fromPhrase(mnemonic, '', path)
  const sig    = wallet.signingKey.sign('0x' + hashHex)
  const r = sig.r.slice(2).padStart(64, '0')
  const s = sig.s.slice(2).padStart(64, '0')
  const v = sig.v.toString(16).padStart(2, '0')
  return r + s + v
}
