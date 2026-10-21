/**
 * 3.10 — sign-hl-binding  (HL recipient binding + actionType-spoof closure)
 *
 * The HL analogue of the #5 binding fix. The withdraw3 recipient lives inside the
 * EIP-712 struct; armory recomputes the hash from the action and extracts that
 * destination, so:
 *   - withdraw3 with a whitelisted `destination` HINT but an action.destination
 *     paying a NON-whitelisted address → denied (the bytes are authoritative)
 *   - withdraw3 honestly paying the whitelisted address → ok
 *   - usdSend honestly paying an internal pool address → ok
 *
 * Plus actionType-spoof closure: because the hash is recomputed from the CLAIMED
 * action's schema, a withdraw-shaped artifact submitted under an auth/internal
 * actionType fails to recompute (missing required fields) → denied.
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'

const WHITELIST     = '0x1111111111111111111111111111111111111111'
const NON_WHITELIST = '0x2222222222222222222222222222222222222222'
const SIGN_PATH     = "m/44'/60'/0'/0/100"

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup({ env: { ARMORY_EXTERNAL_WHITELIST: WHITELIST } })

  const internal = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)

  // withdraw3: whitelisted HINT, but the signed bytes pay a non-whitelisted address.
  const spoof = hlToken({ type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: NON_WHITELIST, amount: '5', time: 1 }, WHITELIST)
  assert((await ctx.client.send(`sign ${SIGN_PATH} withdraw3 ${spoof}`)) === 'err sign request denied',
    'withdraw3 hint=whitelist but bytes=non-whitelist: denied')

  // withdraw3 honestly paying the whitelisted address → ok.
  const honest = hlToken({ type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: WHITELIST, amount: '5', time: 1 }, WHITELIST)
  assert((await ctx.client.send(`sign ${SIGN_PATH} withdraw3 ${honest}`)).startsWith('ok '),
    'withdraw3 honestly paying whitelist: allowed')

  // usdSend honestly paying an internal pool address → ok.
  const xfer = hlToken({ type: 'usdSend', hyperliquidChain: 'Mainnet', destination: internal, amount: '1', time: 1 })
  assert((await ctx.client.send(`sign ${SIGN_PATH} usdSend ${xfer}`)).startsWith('ok '),
    'usdSend to internal pool address: allowed')

  // actionType spoof — a withdraw-shaped action submitted as approveAgent (auth):
  // recompute uses the ApproveAgent schema, whose required fields are absent → denied.
  const withdrawShaped = { type: 'withdraw3', hyperliquidChain: 'Mainnet', destination: NON_WHITELIST, amount: '5', time: 1 }
  assert((await ctx.client.send(`sign ${SIGN_PATH} approveAgent ${hlToken(withdrawShaped)}`)) === 'err sign request denied',
    'auth action carrying a withdraw-shaped artifact: denied (spoof closed)')

  // Same, submitted as usdClassTransfer (internal): missing toPerp/nonce → denied.
  assert((await ctx.client.send(`sign ${SIGN_PATH} usdClassTransfer ${hlToken(withdrawShaped)}`)) === 'err sign request denied',
    'internal action carrying a withdraw-shaped artifact: denied (spoof closed)')

  // positive auth + internal paths, for completeness.
  const approve = hlToken({ type: 'approveAgent', hyperliquidChain: 'Mainnet', agentAddress: WHITELIST, agentName: 'agent', nonce: 1 })
  assert((await ctx.client.send(`sign ${SIGN_PATH} approveAgent ${approve}`)).startsWith('ok '), 'approveAgent positive path: allowed')

  const classXfer = hlToken({ type: 'usdClassTransfer', hyperliquidChain: 'Mainnet', amount: '1', toPerp: true, nonce: 1 })
  assert((await ctx.client.send(`sign ${SIGN_PATH} usdClassTransfer ${classXfer}`)).startsWith('ok '), 'usdClassTransfer positive path: allowed')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
