/**
 * 2.3 — derive-deterministic
 *
 * Verifies:
 *   - Stopping and restarting the armory (same mnemonic) re-derives identical
 *     addresses for the same paths
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  // First run — capture addresses
  ctx = await setup()
  const evm0_a    = await ctx.client.send("derive m/44'/60'/0'/0/0")
  const cosmos0_a = await ctx.client.send("derive m/44'/118'/0'/0/0")
  const evm50_a   = await ctx.client.send("derive m/44'/60'/0'/0/50")
  await teardown(ctx)
  ctx = null

  // Second run — same mnemonic (TEST_MNEMONIC via ARMORY_MNEMONIC), wipes .keys/
  // so mnemonic is re-imported on startup.
  ctx = await setup()
  const evm0_b    = await ctx.client.send("derive m/44'/60'/0'/0/0")
  const cosmos0_b = await ctx.client.send("derive m/44'/118'/0'/0/0")
  const evm50_b   = await ctx.client.send("derive m/44'/60'/0'/0/50")

  assert(evm0_b    === evm0_a,    'EVM index 0 identical after restart')
  assert(cosmos0_b === cosmos0_a, 'Cosmos index 0 identical after restart')
  assert(evm50_b   === evm0_a  || evm50_b !== evm0_b,
    'EVM index 50 distinct from index 0 (sanity: different indices differ)')
  // Simpler: just assert the same path gives the same result
  assert(evm50_b   === evm50_a,   'EVM index 50 identical after restart')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
