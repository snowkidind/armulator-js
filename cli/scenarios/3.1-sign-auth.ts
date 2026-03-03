/**
 * 3.1 — sign-auth
 *
 * Verifies:
 *   - Auth action types (approveAgent, AddAuthenticator, RemoveAuthenticator)
 *     succeed from any index with no destination parameter
 *   - Returned signature is 130 hex chars (65 bytes): r || s || v
 *   - ecrecover on the signature matches the derived address at the signing path
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'
import { recoverAddress }                               from 'ethers'

const HASH         = 'a'.repeat(64)
const EXPECTED_0   = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
const SIG_RE       = /^[0-9a-fA-F]{130}$/

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  // approveAgent from index 0
  const r0 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${HASH}`)
  assert(r0.startsWith('ok '), 'approveAgent index 0: returns ok')
  const sig0 = r0.slice(3)
  assert(SIG_RE.test(sig0), 'approveAgent: signature is 130 hex chars (65 bytes)')

  const recovered = recoverAddress('0x' + HASH, '0x' + sig0)
  assert(
    recovered.toLowerCase() === EXPECTED_0.toLowerCase(),
    'approveAgent: ecrecover matches known index 0 address',
  )

  // AddAuthenticator from index 75 (operational range)
  const r75 = await ctx.client.send(`sign m/44'/60'/0'/0/75 AddAuthenticator ${HASH}`)
  assert(r75.startsWith('ok '), 'AddAuthenticator index 75: returns ok')
  assert(SIG_RE.test(r75.slice(3)), 'AddAuthenticator: signature is 65 bytes')

  // RemoveAuthenticator from index 150 (user account range)
  const r150 = await ctx.client.send(`sign m/44'/60'/0'/0/150 RemoveAuthenticator ${HASH}`)
  assert(r150.startsWith('ok '), 'RemoveAuthenticator index 150: returns ok')
  assert(SIG_RE.test(r150.slice(3)), 'RemoveAuthenticator: signature is 65 bytes')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
