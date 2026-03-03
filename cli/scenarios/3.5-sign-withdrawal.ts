/**
 * 3.5 — sign-withdrawal
 *
 * Verifies withdrawal destination policy:
 *   - Any signing index can withdraw to a whitelisted external address
 *   - Any signing index can withdraw to an internal address
 *     (e.g. withdraw3 from HL back to own on-chain address)
 *   - Withdrawal to a non-whitelisted external address is denied
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const HASH          = 'e'.repeat(64)
const DRAIN         = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
const WHITELIST     = '0x1111111111111111111111111111111111111111'
const NON_WHITELIST = '0x2222222222222222222222222222222222222222'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup({
    env: {
      ARMORY_DRAIN_ADDRESS:      DRAIN,
      ARMORY_EXTERNAL_WHITELIST: WHITELIST,
    },
  })

  const addrInternal = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)

  // Any index can withdraw to a whitelisted external address
  for (const idx of [5, 75, 150]) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/${idx} withdraw3 ${WHITELIST} ${HASH}`)
    assert(r.startsWith('ok '), `withdrawal from index ${idx} to whitelist: allowed`)
  }

  // Any index can also withdraw to an internal address
  // (e.g. withdraw3 from HL back to the same key's Arbitrum address)
  for (const idx of [5, 75, 150]) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/${idx} withdraw3 ${addrInternal} ${HASH}`)
    assert(r.startsWith('ok '), `withdrawal from index ${idx} to internal address: allowed`)
  }

  // evmWithdraw to whitelisted external address
  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/75 evmWithdraw ${WHITELIST} ${HASH}`)
  assert(r1.startsWith('ok '), 'evmWithdraw to whitelist: allowed')

  // Non-whitelisted external address is denied for any withdrawal type
  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/5 withdraw3 ${NON_WHITELIST} ${HASH}`)
  assert(r2 === 'err sign request denied', 'withdrawal to non-whitelisted external: denied')

  const r3 = await ctx.client.send(`sign m/44'/60'/0'/0/75 evmWithdraw ${NON_WHITELIST} ${HASH}`)
  assert(r3 === 'err sign request denied', 'evmWithdraw to non-whitelisted external: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
