/**
 * 3.7 — sign-uniform-errors
 *
 * Verifies that all sign POLICY rejections return the same string:
 *   err sign request denied
 *
 * This prevents the caller from using error differences to probe which check
 * failed (oracle attack). Malformed-input cases (err invalid command) are
 * covered separately in 3.8.
 */
import { setup, teardown, assert, hlToken, evmToken, type ArmoryContext } from './_harness.js'
import { parseEther, parseUnits }                                         from 'ethers'

const ERROR    = 'err sign request denied'
const EXTERNAL = '0x1111111111111111111111111111111111111111'

const usdSend   = (dest: string) => hlToken({ type: 'usdSend', hyperliquidChain: 'Mainnet', destination: dest, amount: '1', time: 1 })
const withdraw3 = (dest: string) => hlToken({ type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: dest, amount: '1', time: 1 })
const evmWdraw  = (dest: string) => evmToken({ to: dest, value: parseEther('0.1'), chainId: 42161, nonce: 1, gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+

  const cases: [string, string][] = [
    ['unknown action type',             `sign m/44'/60'/0'/0/0 order ${usdSend(addr10)}`],
    ['transfer to external address',    `sign m/44'/60'/0'/0/75 usdSend ${usdSend(EXTERNAL)}`],
    ['tier violation: 0-49 → 100+',    `sign m/44'/60'/0'/0/5 usdSend ${usdSend(addr150)}`],
    ['tier violation: 0-49 → 0-49',    `sign m/44'/60'/0'/0/5 usdSend ${usdSend(addr10)}`],
    ['withdrawal not whitelisted',      `sign m/44'/60'/0'/0/5 withdraw3 ${withdraw3('0x3333333333333333333333333333333333333333')}`],
    ['evmWithdraw not whitelisted',     `sign m/44'/60'/0'/0/75 evmWithdraw ${evmWdraw('0x4444444444444444444444444444444444444444')}`],
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
