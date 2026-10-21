/**
 * 3.5 — sign-withdrawal
 *
 * Verifies withdrawal policy against the recipient EXTRACTED from the signed bytes:
 *   - Any signing index can withdraw to a whitelisted external address
 *   - Any signing index can withdraw to an internal address
 *     (e.g. withdraw3 from HL back to own on-chain address)
 *   - Withdrawal to a non-whitelisted external address is denied
 *   - Both HL withdraw3 (hl-action) and EVM evmWithdraw (evm-tx) honor the policy
 */
import { setup, teardown, assert, hlToken, evmToken, type ArmoryContext } from './_harness.js'
import { parseEther, parseUnits }                                         from 'ethers'

const DRAIN         = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
const WHITELIST     = '0x1111111111111111111111111111111111111111'
const NON_WHITELIST = '0x2222222222222222222222222222222222222222'

const withdraw3  = (dest: string) => hlToken({ type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: dest, amount: '5', time: 1 })
const evmWdraw   = (dest: string) => evmToken({ to: dest, value: parseEther('0.1'), chainId: 42161, nonce: 1, gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup({ env: { ARMORY_DRAIN_ADDRESS: DRAIN, ARMORY_EXTERNAL_WHITELIST: WHITELIST } })

  const addrInternal = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)

  // Any index can withdraw3 to a whitelisted external address
  for (const idx of [5, 75, 150]) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/${idx} withdraw3 ${withdraw3(WHITELIST)}`)
    assert(r.startsWith('ok '), `withdraw3 from index ${idx} to whitelist: allowed`)
  }

  // Any index can also withdraw3 to an internal address
  for (const idx of [5, 75, 150]) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/${idx} withdraw3 ${withdraw3(addrInternal)}`)
    assert(r.startsWith('ok '), `withdraw3 from index ${idx} to internal address: allowed`)
  }

  // evmWithdraw (native EVM tx) to whitelisted external address
  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/75 evmWithdraw ${evmWdraw(WHITELIST)}`)
  assert(r1.startsWith('ok '), 'evmWithdraw to whitelist: allowed')

  // Non-whitelisted external address is denied for either withdrawal type
  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/5 withdraw3 ${withdraw3(NON_WHITELIST)}`)
  assert(r2 === 'err sign request denied', 'withdraw3 to non-whitelisted external: denied')

  const r3 = await ctx.client.send(`sign m/44'/60'/0'/0/75 evmWithdraw ${evmWdraw(NON_WHITELIST)}`)
  assert(r3 === 'err sign request denied', 'evmWithdraw to non-whitelisted external: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
