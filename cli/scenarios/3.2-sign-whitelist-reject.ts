/**
 * 3.2 — sign-whitelist-reject
 *
 * Verifies:
 *   - Action types not in the descriptor registry return err sign request denied
 *   - This applies regardless of signing index or (well-formed) artifact
 */
import { setup, teardown, assert, evmToken, type ArmoryContext } from './_harness.js'
import { parseEther, parseUnits }                                from 'ethers'

const INTERNAL_TO = '0x1111111111111111111111111111111111111111'

// A well-formed evm-tx artifact so the request passes base64/JSON parsing; the
// rejection must come purely from the unknown actionType, not malformed input.
const TOKEN = evmToken({
  to: INTERNAL_TO, value: parseEther('0.1'), chainId: 42161, nonce: 0,
  gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2,
})

const UNKNOWN_TYPES = ['order', 'cancel', 'cancelOrder', 'placeOrder', 'trade', 'marketOrder', 'limitOrder']

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  for (const t of UNKNOWN_TYPES) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/0 ${t} ${TOKEN}`)
    assert(r === 'err sign request denied', `unknown action type "${t}" → denied`)
  }

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
