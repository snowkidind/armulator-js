/**
 * 3.1 — sign-auth
 *
 * Verifies the destination-binding wire form for HL auth actions:
 *   - auth actions (approveAgent, userSetAbstraction) succeed from any index with
 *     no external recipient
 *   - response is `ok <derivedAddress> <signature130hex>` (signer address returned)
 *   - the returned address equals the derived address at the signing path
 *   - the signature recovers over the hash armory RECOMPUTED from the action
 *     (proving the signed bytes are bound to the claimed action, not a caller digest)
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'
import { recoverAddress }                                       from 'ethers'
import { hashApproveAgent, hashUserSetAbstraction }             from '../../src/hl/typedData.js'

const EXPECTED_0 = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
const SIG_RE     = /^[0-9a-fA-F]{130}$/
const AGENT      = '0x1111111111111111111111111111111111111111'

function parseOk(r: string): { addr: string; sig: string } {
  const [addr, sig] = r.slice(3).split(' ')
  return { addr, sig }
}

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  // approveAgent from index 0 — verify address + hash binding end to end.
  const approveAction = { type: 'approveAgent', hyperliquidChain: 'Mainnet', agentAddress: AGENT, agentName: 'test-agent', nonce: 1 }
  const r0 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${hlToken(approveAction)}`)
  assert(r0.startsWith('ok '), 'approveAgent index 0: returns ok')
  const { addr: addr0, sig: sig0 } = parseOk(r0)
  assert(SIG_RE.test(sig0), 'approveAgent: signature is 130 hex chars (65 bytes)')
  assert(addr0.toLowerCase() === EXPECTED_0.toLowerCase(), 'approveAgent: returned address is the index 0 signer')

  // The signature must recover over the hash armory recomputed from the action.
  const expectedHash = hashApproveAgent(approveAction)
  const recovered    = recoverAddress('0x' + expectedHash, '0x' + sig0)
  assert(recovered.toLowerCase() === EXPECTED_0.toLowerCase(), 'approveAgent: sig recovers over the RECOMPUTED hash to the signer')

  // userSetAbstraction from index 75 (operational range).
  const absAction = { type: 'userSetAbstraction', hyperliquidChain: 'Mainnet', user: EXPECTED_0, abstraction: 'disabled', nonce: 2 }
  const r75 = await ctx.client.send(`sign m/44'/60'/0'/0/75 userSetAbstraction ${hlToken(absAction)}`)
  assert(r75.startsWith('ok '), 'userSetAbstraction index 75: returns ok')
  const { addr: addr75, sig: sig75 } = parseOk(r75)
  assert(SIG_RE.test(sig75), 'userSetAbstraction: signature is 65 bytes')
  const rec75 = recoverAddress('0x' + hashUserSetAbstraction(absAction), '0x' + sig75)
  assert(rec75.toLowerCase() === addr75.toLowerCase(), 'userSetAbstraction: sig recovers over the RECOMPUTED hash to the returned address')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
