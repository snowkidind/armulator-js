/**
 * 3.2 — sign-whitelist-reject
 *
 * Verifies:
 *   - Action types not in the whitelist return err sign request denied
 *   - This applies regardless of signing index or hash value
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const HASH = 'b'.repeat(64)

const UNKNOWN_TYPES = [
  'order',
  'cancel',
  'cancelOrder',
  'placeOrder',
  'trade',
  'marketOrder',
  'limitOrder',
]

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  for (const t of UNKNOWN_TYPES) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/0 ${t} ${HASH}`)
    assert(r === 'err sign request denied', `unknown action type "${t}" → denied`)
  }

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
