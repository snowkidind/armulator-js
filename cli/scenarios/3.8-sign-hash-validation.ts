/**
 * 3.8 — sign-input-validation
 *
 * Verifies that MALFORMED input returns err invalid command (not sign request
 * denied). In the destination-binding wire form the sign payload is a single
 * base64url(requestJSON) token, so "malformed" now means:
 *   - wrong number of whitespace-delimited arguments
 *   - a token that is not base64url / not valid JSON
 *   - a request missing/!matching the artifact the action expects
 *   - a bad signing path
 *
 * (Policy failures — denied — are covered in 3.5/3.7; here every case is structural.)
 */
import { setup, teardown, assert, encodeRequest, hlToken, evmToken, type ArmoryContext } from './_harness.js'
import { parseEther, parseUnits }                                                         from 'ethers'

const INVALID = 'err invalid command'

const goodHlToken = hlToken({ type: 'approveAgent', hyperliquidChain: 'Mainnet', agentAddress: '0x1111111111111111111111111111111111111111', agentName: 'a', nonce: 1 })
const goodEvmToken = evmToken({ to: '0x1111111111111111111111111111111111111111', value: parseEther('0.1'), chainId: 42161, nonce: 1, gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 })

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  // Too few arguments (path + actionType, no token)
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent`)) === INVALID, 'missing token: invalid command')

  // Too many arguments (an extra whitespace-delimited token)
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${goodHlToken} extra`)) === INVALID, 'extra argument: invalid command')

  // Token contains a non-base64url character
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent abc*def`)) === INVALID, 'non-base64url token: invalid command')

  // Valid base64url but not JSON
  const notJson = Buffer.from('hello', 'utf8').toString('base64url')
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${notJson}`)) === INVALID, 'base64url but not JSON: invalid command')

  // JSON missing the artifact
  const noArtifact = encodeRequest({ destination: '0x1111111111111111111111111111111111111111' })
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${noArtifact}`)) === INVALID, 'missing artifact: invalid command')

  // Artifact kind does not match the action (approveAgent expects hl-action)
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${goodEvmToken}`)) === INVALID, 'artifact kind mismatch: invalid command')

  // hl-action with a non-object action
  const badAction = encodeRequest({ artifact: { kind: 'hl-action', action: 'nope' } })
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${badAction}`)) === INVALID, 'hl-action non-object action: invalid command')

  // evm-tx with a non-string unsignedTx
  const badEvm = encodeRequest({ artifact: { kind: 'evm-tx', unsignedTx: 123 } })
  assert((await ctx.client.send(`sign m/44'/60'/0'/0/5 transfer ${badEvm}`)) === INVALID, 'evm-tx non-string unsignedTx: invalid command')

  // Bad signing path
  assert((await ctx.client.send(`sign notapath approveAgent ${goodHlToken}`)) === INVALID, 'bad path: invalid command')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
