/**
 * Action type whitelist, destination policy, and hash signing.
 *
 * Action categories:
 *   auth       — no destination (approveAgent, AddAuthenticator, etc.)
 *   transfer   — destination must be in internal pool; index tier applies
 *   withdrawal — destination must be in external whitelist
 *
 * Transfer tier rules:
 *   Signing index 0–49  → destination must be in indices 50–99 (staging door)
 *   Signing index 50+   → destination may be anywhere in internal pool
 *
 * Withdrawal rules (any signing index):
 *   Destination must be in external whitelist (ARMORY_EXTERNAL_WHITELIST or
 *   ARMORY_DRAIN_ADDRESS). Internal addresses are never valid withdrawal destinations.
 */
import { HDNodeWallet }                      from 'ethers'
import { pathIndex }                         from './derivation.js'
import { getExternalWhitelist, getDrainAddress } from './policy.js'
import type { AddressPool }                  from './derivation.js'

// ── Action type whitelist ─────────────────────────────────────────────────────

type ActionCategory = 'auth' | 'transfer' | 'withdrawal'

const ACTION_WHITELIST = new Map<string, ActionCategory>([
  // ── Hyperliquid ───────────────────────────────────────────────────────────
  ['approveAgent',              'auth'      ],  // authorize ephemeral agent key
  ['usdSend',                   'transfer'  ],  // USDC peer-to-peer on HL L2
  ['spotSend',                  'transfer'  ],  // spot token (HYPE, etc.) peer-to-peer on HL L2
  ['withdraw3',                 'withdrawal'],  // USDC or spot token from HL L2 → external L1 address (Arbitrum, Solana, etc.); one action type covers all assets
  // ── EVM on-chain (any chain) ──────────────────────────────────────────────
  ['transfer',                  'transfer'  ],  // ERC-20 or native send to internal address
  ['evmWithdraw',               'withdrawal'],  // ERC-20 or native send to external whitelist
  // ── dYdX / Cosmos ─────────────────────────────────────────────────────────
  ['AddAuthenticator',          'auth'      ],  // register permissioned trading key
  ['RemoveAuthenticator',       'auth'      ],  // revoke permissioned trading key
  ['MsgTransfer',               'transfer'  ],  // transfer between accounts on-chain
  ['MsgSend',                   'transfer'  ],  // native token send (gas distribution)
  ['MsgWithdrawFromSubaccount', 'withdrawal'],  // withdraw from dYdX subaccount
])

export function getCategory(actionType: string): ActionCategory | null {
  return ACTION_WHITELIST.get(actionType) ?? null
}

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
 * Check the destination policy for a sign request.
 * Returns true if the request is permitted, false if it must be denied.
 */
export function checkPolicy(
  signingPath: string,
  actionType:  string,
  destination: string | null,
  pool:        AddressPool,
): boolean {
  const category = getCategory(actionType)
  if (!category) return false

  if (category === 'auth') return destination === null

  if (destination === null) return false

  const signingIdx = pathIndex(signingPath)

  if (category === 'transfer') {
    const destIdx = getInternalIndex(destination, pool)
    if (destIdx === null) return false           // not an internal address
    if (signingIdx <= 49) return destIdx >= 50 && destIdx <= 99
    return true                                  // 50+: any internal address
  }

  // withdrawal: internal pool OR external whitelist
  // (e.g. withdraw3 back to own on-chain address, or evmWithdraw to second armory)
  if (getInternalIndex(destination, pool) !== null) return true
  return isExternalWhitelisted(destination)
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
