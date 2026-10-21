/**
 * 3.6 — sign-withdraw-drain
 *
 * Verifies drain address behaviour, against the recipient extracted from the
 * signed withdraw3 bytes:
 *   - When ARMORY_DRAIN_ADDRESS is set, withdrawal to it succeeds from any index
 *   - When ARMORY_DRAIN_ADDRESS is not set, the drain path is unavailable
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'

const DRAIN = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
const withdraw3 = (dest: string) => hlToken({ type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: dest, amount: '5', time: 1 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  // Part A — drain address configured
  ctx = await setup({ env: { ARMORY_DRAIN_ADDRESS: DRAIN } })

  for (const idx of [5, 75, 150]) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/${idx} withdraw3 ${withdraw3(DRAIN)}`)
    assert(r.startsWith('ok '), `drain withdrawal from index ${idx}: allowed`)
  }

  await teardown(ctx)
  ctx = null

  // Part B — no drain address configured
  ctx = await setup()   // ARMORY_DRAIN_ADDRESS not set

  const r = await ctx.client.send(`sign m/44'/60'/0'/0/5 withdraw3 ${withdraw3(DRAIN)}`)
  assert(r === 'err sign request denied', 'withdrawal to drain when unconfigured: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
