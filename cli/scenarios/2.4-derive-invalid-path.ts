/**
 * 2.4 — derive-invalid-path
 *
 * Verifies:
 *   - Malformed paths return `err invalid command`
 *   - Valid format but unsupported coin type returns `err invalid command`
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const INVALID_PATHS = [
  "m/44'/60'/abc",          // non-numeric segment
  '',                        // empty
  "44'/60'/0'/0/0",         // missing leading m/
  "m/44'/60'/0'/0/",        // trailing slash
  "m/44'/60'/0'/0/ 0",      // whitespace in segment
  "m/44'/60'/0'/0/0/extra/segment/that/is/fine",  // deep but valid format — should succeed, not fail
]

// These are syntactically invalid — must return err invalid command
const MUST_FAIL = [
  "m/44'/60'/abc",
  '',
  "44'/60'/0'/0/0",
  "m/44'/60'/0'/0/",
]

// Valid format, unsupported coin type → err invalid command
const UNSUPPORTED_COIN = "m/44'/999'/0'/0/0"

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  for (const path of MUST_FAIL) {
    const r = await ctx.client.send(`derive ${path}`)
    assert(r === 'err invalid command', `invalid path "${path}" → err invalid command`)
  }

  // Unsupported coin type
  const rCoin = await ctx.client.send(`derive ${UNSUPPORTED_COIN}`)
  assert(rCoin === 'err invalid command', 'unsupported coin type → err invalid command')

  // Empty derive (no path arg)
  const rEmpty = await ctx.client.send('derive')
  assert(rEmpty === 'err invalid command', 'derive with no path → err invalid command')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
