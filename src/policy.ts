/**
 * Hardcoded policy: external withdrawal whitelist and drain address.
 *
 * Production: edit EXTERNAL_WHITELIST_DEFAULT and DRAIN_ADDRESS_DEFAULT directly.
 * Testing:    override via ARMORY_EXTERNAL_WHITELIST (comma-separated) and
 *             ARMORY_DRAIN_ADDRESS env vars — mirrors the ARMORY_MNEMONIC pattern.
 *
 * External whitelist:  EVM or Cosmos bech32 addresses outside the mnemonic's
 *                      HD tree (second armory tiers, hot withdrawal wallets).
 *                      No entry cap. Whitelisted for withdrawal from any index.
 * Drain address:       emergency fund recovery. Must be a multisig in production.
 *                      Whitelisted for withdrawal from any signing index.
 *                      Leave empty string to disable.
 *
 * On the TamaGo firmware these are compiled-in constants with no env var override.
 */
import { isAddress } from 'ethers'

function isValidWhitelistEntry(addr: string): boolean {
  if (isAddress(addr)) return true
  // Cosmos-family bech32: cosmos1, dydx1, or any hrp1... pattern
  return /^[a-z]+1[a-z0-9]{38,}$/.test(addr)
}

// ── Hardcoded defaults — edit for production deployment ───────────────────────

const EXTERNAL_WHITELIST_DEFAULT: string[] = [
  // '0xYourHotWithdrawalWalletAddress',
]

const DRAIN_ADDRESS_DEFAULT: string = ''

// ── Runtime accessors (env var overrides for dev/test only) ───────────────────

export function getExternalWhitelist(): string[] {
  const env = process.env.ARMORY_EXTERNAL_WHITELIST
  if (env) return env.split(',').map(a => a.trim()).filter(Boolean)
  return EXTERNAL_WHITELIST_DEFAULT
}

export function getDrainAddress(): string {
  return process.env.ARMORY_DRAIN_ADDRESS?.trim() ?? DRAIN_ADDRESS_DEFAULT
}

// ── Startup validation ────────────────────────────────────────────────────────

/**
 * Validate all policy addresses at startup.
 * Throws if any entry is malformed — the armory must not start with bad policy.
 */
export function validatePolicy(): void {
  const whitelist = getExternalWhitelist()
  const drain     = getDrainAddress()

  for (const addr of whitelist) {
    if (!isValidWhitelistEntry(addr)) {
      throw new Error(`external whitelist contains invalid address: ${addr}`)
    }
  }
  if (drain && !isAddress(drain)) {
    throw new Error(`drain address is not a valid EVM address: ${drain}`)
  }
}
