/**
 * 2.2 — derive-cosmos
 *
 * Verifies:
 *   - derive m/44'/118'/0'/0/0 returns a valid bech32 cosmos1... address
 *     for the test mnemonic
 *   - Multiple indices return distinct addresses
 *   - All returned addresses match the bech32 cosmos1 format
 *
 * Note: dYdX (dydx1 prefix) is Phase 4.
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

// Known cosmos1 addresses for the test mnemonic.
const EXPECTED_COSMOS_0 = 'cosmos119rl4cm2hmr8afy4kldpxz3fka4jguq0acw6xtx'
const EXPECTED_COSMOS_1 = 'cosmos11jrkmdcwgq94uaamx6zax2luewlhf7u4kck32z3'

// bech32 cosmos1 address: prefix + bech32 chars (lowercase alphanumeric + some specials)
const COSMOS_RE = /^cosmos1[a-z0-9]{38,}$/

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const r0 = await ctx.client.send("derive m/44'/118'/0'/0/0")
  const r1 = await ctx.client.send("derive m/44'/118'/0'/0/1")

  assert(r0 === `ok ${EXPECTED_COSMOS_0}`, 'cosmos index 0 matches expected address')
  assert(r1 === `ok ${EXPECTED_COSMOS_1}`, 'cosmos index 1 matches expected address')

  const addr0 = r0.slice(3)
  const addr1 = r1.slice(3)

  assert(COSMOS_RE.test(addr0), 'cosmos index 0 is valid cosmos1 bech32')
  assert(COSMOS_RE.test(addr1), 'cosmos index 1 is valid cosmos1 bech32')
  assert(addr0 !== addr1,       'cosmos indices 0 and 1 are distinct')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
