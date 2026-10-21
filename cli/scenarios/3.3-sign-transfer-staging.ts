/**
 * 3.3 — sign-transfer-staging
 *
 * Verifies the 0–49 staging tier, enforced against the recipient EXTRACTED from
 * the signed bytes:
 *   - Transfer from index 0–49: recipient in 50–99 succeeds
 *   - Transfer from index 0–49: recipient in 0–49 fails
 *   - Transfer from index 0–49: recipient in 100+ fails
 *   - Rule applies to HL transfer types (usdSend, spotSend) and EVM `transfer`
 */
import { setup, teardown, assert, hlToken, evmToken, type ArmoryContext } from './_harness.js'
import { parseEther, parseUnits }                                         from 'ethers'

const SIGNING_PATH = "m/44'/60'/0'/0/5"   // index 5, inside 0–49

const usdSend  = (dest: string) => hlToken({ type: 'usdSend',  hyperliquidChain: 'Mainnet', destination: dest, amount: '1', time: 1 })
const spotSend = (dest: string) => hlToken({ type: 'spotSend', hyperliquidChain: 'Mainnet', destination: dest, token: 'HYPE', amount: '1', time: 1 })
const evmXfer  = (dest: string) => evmToken({ to: dest, value: parseEther('0.1'), chainId: 42161, nonce: 1, gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr75  = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)   // 50–99 ✓
  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49  ✗
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+  ✗

  // HL usdSend
  assert((await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${usdSend(addr75)}`)).startsWith('ok '), 'usdSend 0-49 → 50-99: allowed')
  assert((await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${usdSend(addr10)}`)) === 'err sign request denied', 'usdSend 0-49 → 0-49: denied')
  assert((await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${usdSend(addr150)}`)) === 'err sign request denied', 'usdSend 0-49 → 100+: denied')

  // HL spotSend
  assert((await ctx.client.send(`sign ${SIGNING_PATH} spotSend ${spotSend(addr75)}`)).startsWith('ok '), 'spotSend 0-49 → 50-99: allowed')
  assert((await ctx.client.send(`sign ${SIGNING_PATH} spotSend ${spotSend(addr10)}`)) === 'err sign request denied', 'spotSend 0-49 → 0-49: denied')

  // EVM transfer (native) — recipient decoded from the tx `to`
  assert((await ctx.client.send(`sign ${SIGNING_PATH} transfer ${evmXfer(addr75)}`)).startsWith('ok '), 'transfer(EVM) 0-49 → 50-99: allowed')
  assert((await ctx.client.send(`sign ${SIGNING_PATH} transfer ${evmXfer(addr10)}`)) === 'err sign request denied', 'transfer(EVM) 0-49 → 0-49: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
