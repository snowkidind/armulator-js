/**
 * 3.4 — sign-transfer-high
 *
 * Verifies that signing index 50+ can transfer to any internal address:
 *   - From 50–99: destinations in 0–49, 50–99, and 100+ all succeed
 *   - From 100+:  destinations in 0–49, 50–99, and 100+ all succeed
 *   - External address always denied for transfer action types
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const HASH     = 'd'.repeat(64)
const EXTERNAL = '0x1111111111111111111111111111111111111111'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49
  const addr60  = (await ctx.client.send("derive m/44'/60'/0'/0/60")).slice(3)   // 50–99
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+

  // Transfer from index 75 (50–99) — any internal address allowed
  for (const [label, addr] of [['0-49', addr10], ['50-99', addr60], ['100+', addr150]] as const) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/75 usdSend ${addr} ${HASH}`)
    assert(r.startsWith('ok '), `transfer from 50-99 → ${label}: allowed`)
  }

  // Transfer from index 150 (100+) — any internal address allowed
  for (const [label, addr] of [['0-49', addr10], ['50-99', addr60], ['100+', addr150]] as const) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/150 usdSend ${addr} ${HASH}`)
    assert(r.startsWith('ok '), `transfer from 100+ → ${label}: allowed`)
  }

  // External address always denied for any transfer type
  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/75 usdSend ${EXTERNAL} ${HASH}`)
  assert(r1 === 'err sign request denied', 'transfer from 50-99 → external: denied')

  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/150 usdSend ${EXTERNAL} ${HASH}`)
  assert(r2 === 'err sign request denied', 'transfer from 100+ → external: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
