/**
 * 3.7 — sign-uniform-errors
 *
 * Verifies that all sign rejection types return the same error string:
 *   err sign request denied
 *
 * This prevents the caller from using error differences to probe which
 * check failed (oracle attack).
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const HASH  = 'a'.repeat(64)
const ERROR = 'err sign request denied'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+

  const cases: [string, string][] = [
    ['unknown action type',                `sign m/44'/60'/0'/0/0 order ${HASH}`],
    ['transfer to external address',       `sign m/44'/60'/0'/0/75 usdSend 0x1111111111111111111111111111111111111111 ${HASH}`],
    ['tier violation: 0-49 → 100+',       `sign m/44'/60'/0'/0/5 usdSend ${addr150} ${HASH}`],
    ['tier violation: 0-49 → 0-49',       `sign m/44'/60'/0'/0/5 usdSend ${addr10} ${HASH}`],
    ['withdrawal not whitelisted',         `sign m/44'/60'/0'/0/5 withdraw3 0x3333333333333333333333333333333333333333 ${HASH}`],
    ['evmWithdraw not whitelisted',        `sign m/44'/60'/0'/0/75 evmWithdraw 0x4444444444444444444444444444444444444444 ${HASH}`],
  ]

  for (const [label, cmd] of cases) {
    const r = await ctx.client.send(cmd)
    assert(r === ERROR, `${label}: uniform error response`)
  }

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
