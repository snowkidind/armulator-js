/**
 * 3.4 — sign-transfer-high
 *
 * Verifies that signing index 50+ can transfer to any internal address, checked
 * against the recipient extracted from the signed bytes:
 *   - From 50–99: recipients in 0–49, 50–99, and 100+ all succeed
 *   - From 100+:  recipients in 0–49, 50–99, and 100+ all succeed
 *   - External recipient always denied for transfer action types
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'

const EXTERNAL = '0x1111111111111111111111111111111111111111'
const usdSend  = (dest: string) => hlToken({ type: 'usdSend', hyperliquidChain: 'Mainnet', destination: dest, amount: '1', time: 1 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49
  const addr60  = (await ctx.client.send("derive m/44'/60'/0'/0/60")).slice(3)   // 50–99
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+

  for (const [label, addr] of [['0-49', addr10], ['50-99', addr60], ['100+', addr150]] as const) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/75 usdSend ${usdSend(addr)}`)
    assert(r.startsWith('ok '), `transfer from 50-99 → ${label}: allowed`)
  }

  for (const [label, addr] of [['0-49', addr10], ['50-99', addr60], ['100+', addr150]] as const) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/150 usdSend ${usdSend(addr)}`)
    assert(r.startsWith('ok '), `transfer from 100+ → ${label}: allowed`)
  }

  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/75 usdSend ${usdSend(EXTERNAL)}`)
  assert(r1 === 'err sign request denied', 'transfer from 50-99 → external: denied')

  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/150 usdSend ${usdSend(EXTERNAL)}`)
  assert(r2 === 'err sign request denied', 'transfer from 100+ → external: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
