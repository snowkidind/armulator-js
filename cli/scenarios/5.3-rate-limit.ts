/**
 * 5.3 — rate-limit
 *
 * Verifies that sign commands are throttled to 10 per second per connection.
 *
 * Fires 15 sign requests in rapid succession (well under 1 second).
 * Expects at most 10 to succeed and at least 5 to be rate-limited.
 *
 * ArmoryClient queues all writes immediately so all 15 frames hit the server
 * within milliseconds; the server processes them sequentially and applies
 * the sliding-window rate limit.
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'

// A valid approveAgent request (auth, no recipient) so each under-limit sign
// returns `ok ...`; the rate limiter is what caps the count.
const TOKEN   = hlToken({ type: 'approveAgent', hyperliquidChain: 'Mainnet', agentAddress: '0x1111111111111111111111111111111111111111', agentName: 'a', nonce: 1 })
const TOTAL   = 15
const MAX_OK  = 10

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  // Fire all 15 sign requests without awaiting individually — they all enqueue
  // immediately and the server sees them within the same 1-second window.
  const promises: Promise<string>[] = []
  for (let i = 0; i < TOTAL; i++) {
    promises.push(ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${TOKEN}`))
  }
  const results = await Promise.all(promises)

  const okCount      = results.filter(r => r.startsWith('ok ')).length
  const limitedCount = results.filter(r => r === 'err rate limit exceeded').length
  const otherCount   = results.filter(r => !r.startsWith('ok ') && r !== 'err rate limit exceeded').length

  assert(otherCount === 0,           `no unexpected responses (got ${otherCount})`)
  assert(okCount <= MAX_OK,          `at most ${MAX_OK} sign requests pass (got ${okCount})`)
  assert(limitedCount >= TOTAL - MAX_OK, `at least ${TOTAL - MAX_OK} rate-limited (got ${limitedCount})`)
  assert(okCount + limitedCount === TOTAL, 'all responses accounted for')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
