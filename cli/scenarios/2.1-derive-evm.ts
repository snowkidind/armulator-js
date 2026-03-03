/**
 * 2.1 — derive-evm
 *
 * Verifies:
 *   - derive m/44'/60'/0'/0/0 returns the expected EIP-55 checksummed address
 *     for the test mnemonic
 *   - Multiple indices return distinct addresses
 *   - All returned addresses match EIP-55 format (0x + 40 hex chars)
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

// Known addresses for the test mnemonic (abandon × 11 + about).
// Verified against independent derivation.
const EXPECTED_EVM_0  = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
const EXPECTED_EVM_1  = '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0'
const EXPECTED_EVM_99 = '0x00c0D379323ff700B476C8A8B4a0C72356D2D399'

const EIP55_RE = /^0x[0-9a-fA-F]{40}$/

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const r0  = await ctx.client.send("derive m/44'/60'/0'/0/0")
  const r1  = await ctx.client.send("derive m/44'/60'/0'/0/1")
  const r99 = await ctx.client.send("derive m/44'/60'/0'/0/99")

  assert(r0  === `ok ${EXPECTED_EVM_0}`,  'index 0 matches expected address')
  assert(r1  === `ok ${EXPECTED_EVM_1}`,  'index 1 matches expected address')
  assert(r99 === `ok ${EXPECTED_EVM_99}`, 'index 99 matches expected address')

  const addr0  = r0.slice(3)
  const addr1  = r1.slice(3)
  const addr99 = r99.slice(3)

  assert(EIP55_RE.test(addr0),  'index 0 is EIP-55 hex address')
  assert(EIP55_RE.test(addr1),  'index 1 is EIP-55 hex address')
  assert(EIP55_RE.test(addr99), 'index 99 is EIP-55 hex address')

  assert(addr0 !== addr1,  'indices 0 and 1 are distinct')
  assert(addr0 !== addr99, 'indices 0 and 99 are distinct')
  assert(addr1 !== addr99, 'indices 1 and 99 are distinct')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
