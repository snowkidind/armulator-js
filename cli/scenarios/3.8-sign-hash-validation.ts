/**
 * 3.8 — sign-hash-validation
 *
 * Verifies that malformed inputs return err invalid command (not sign request denied):
 *   - Hash is not exactly 64 hex chars
 *   - Destination is not a valid address format
 *   - Wrong number of arguments for the action category
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'

const GOOD_HASH = 'a'.repeat(64)

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const addr75 = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)

  // Hash too short
  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent tooshort`)
  assert(r1 === 'err invalid command', 'short hash: invalid command')

  // Hash contains non-hex chars
  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${'z'.repeat(64)}`)
  assert(r2 === 'err invalid command', 'non-hex hash: invalid command')

  // Hash too long (65 bytes = 130 chars)
  const r3 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${'a'.repeat(65)}`)
  assert(r3 === 'err invalid command', 'oversized hash: invalid command')

  // Transfer: destination is not a valid address
  const r4 = await ctx.client.send(`sign m/44'/60'/0'/0/5 usdSend notanaddress ${GOOD_HASH}`)
  assert(r4 === 'err invalid command', 'invalid destination format: invalid command')

  // Transfer: missing destination (only hash provided, parsed as dest)
  const r5 = await ctx.client.send(`sign m/44'/60'/0'/0/5 usdSend ${GOOD_HASH}`)
  assert(r5 === 'err invalid command', 'transfer missing destination: invalid command')

  // Auth: extra argument provided (auth expects exactly path + type + hash = 1 in rest)
  const r6 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${addr75} ${GOOD_HASH}`)
  assert(r6 === 'err invalid command', 'auth with extra argument: invalid command')

  // Transfer: missing hash (only destination provided)
  const r7 = await ctx.client.send(`sign m/44'/60'/0'/0/5 usdSend ${addr75}`)
  assert(r7 === 'err invalid command', 'transfer missing hash: invalid command')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
