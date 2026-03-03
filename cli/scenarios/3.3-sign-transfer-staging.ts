/**
 * 3.3 — sign-transfer-staging
 *
 * Verifies the 0–49 staging tier:
 *   - Transfer from index 0–49: destination in 50–99 succeeds
 *   - Transfer from index 0–49: destination in 0–49 fails
 *   - Transfer from index 0–49: destination in 100+ fails
 *   - Rule applies to all transfer action types (usdSend, spotSend, transfer, etc.)
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const HASH         = 'c'.repeat(64)
const SIGNING_PATH = "m/44'/60'/0'/0/5"   // index 5, inside 0–49

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr75  = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)   // 50–99 ✓
  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)   // 0–49  ✗
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)  // 100+  ✗

  // Valid: destination in 50–99
  const r1 = await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${addr75} ${HASH}`)
  assert(r1.startsWith('ok '), 'transfer 0-49 → 50-99: allowed')

  // Invalid: destination in 0–49
  const r2 = await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${addr10} ${HASH}`)
  assert(r2 === 'err sign request denied', 'transfer 0-49 → 0-49: denied')

  // Invalid: destination in 100+ (user accounts)
  const r3 = await ctx.client.send(`sign ${SIGNING_PATH} usdSend ${addr150} ${HASH}`)
  assert(r3 === 'err sign request denied', 'transfer 0-49 → 100+: denied')

  // Same rules apply to spotSend
  const r4 = await ctx.client.send(`sign ${SIGNING_PATH} spotSend ${addr75} ${HASH}`)
  assert(r4.startsWith('ok '), 'spotSend 0-49 → 50-99: allowed')

  const r5 = await ctx.client.send(`sign ${SIGNING_PATH} spotSend ${addr10} ${HASH}`)
  assert(r5 === 'err sign request denied', 'spotSend 0-49 → 0-49: denied')

  // Same rules apply to EVM transfer action type
  const r6 = await ctx.client.send(`sign ${SIGNING_PATH} transfer ${addr75} ${HASH}`)
  assert(r6.startsWith('ok '), 'transfer(EVM) 0-49 → 50-99: allowed')

  const r7 = await ctx.client.send(`sign ${SIGNING_PATH} transfer ${addr10} ${HASH}`)
  assert(r7 === 'err sign request denied', 'transfer(EVM) 0-49 → 0-49: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
