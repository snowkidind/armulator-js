/**
 * 2.5 — internal-pool
 *
 * Verifies:
 *   - All 100 EVM addresses (indices 0–99) are derivable via the derive command
 *   - All 100 are distinct (no collisions)
 *   - All match EIP-55 format
 *   - Spot-check: indices 0 and 99 match the known expected values for the
 *     test mnemonic
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const EXPECTED_EVM_0  = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
const EXPECTED_EVM_99 = '0x00c0D379323ff700B476C8A8B4a0C72356D2D399'
const EIP55_RE = /^0x[0-9a-fA-F]{40}$/

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addresses: string[] = []
  for (let i = 0; i < 100; i++) {
    const r = await ctx.client.send(`derive m/44'/60'/0'/0/${i}`)
    assert(r.startsWith('ok '), `index ${i} returns ok response`)
    addresses.push(r.slice(3))
  }

  // Format check
  for (let i = 0; i < 100; i++) {
    assert(EIP55_RE.test(addresses[i]), `index ${i} is valid EIP-55 address`)
  }

  // Uniqueness
  const unique = new Set(addresses.map(a => a.toLowerCase()))
  assert(unique.size === 100, 'all 100 EVM addresses are distinct')

  // Spot-checks against known values
  assert(addresses[0]  === EXPECTED_EVM_0,  'index 0 matches known expected address')
  assert(addresses[99] === EXPECTED_EVM_99, 'index 99 matches known expected address')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
