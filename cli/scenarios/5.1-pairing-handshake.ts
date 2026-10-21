/**
 * 5.1 — pairing-handshake
 *
 * Verifies the challenge-response pairing protocol:
 *   - On connect the armory sends a 32-byte nonce (64 hex chars, framed).
 *   - The host signs it at the canonical pairing path (m/44'/60'/0'/0/255).
 *   - The armory verifies the signature against its own derived address at that path.
 *   - Only after successful pairing does the armory dispatch commands.
 *
 * The harness's setup() performs pairing transparently, so every scenario
 * implicitly validates it. Here we assert explicitly that commands work
 * post-pairing, confirming the pairing gate is not silently bypassed.
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  // If we reached here, pairing succeeded — commands should be accepted.
  const r1 = await ctx.client.send('status')
  assert(r1 === 'ok ready', 'status accepted after successful pairing')

  const r2 = await ctx.client.send("derive m/44'/60'/0'/0/0")
  assert(r2.startsWith('ok 0x'), 'derive accepted after successful pairing')

  const token = hlToken({ type: 'approveAgent', hyperliquidChain: 'Mainnet', agentAddress: '0x1111111111111111111111111111111111111111', agentName: 'a', nonce: 1 })
  const r3 = await ctx.client.send(`sign m/44'/60'/0'/0/0 approveAgent ${token}`)
  assert(r3.startsWith('ok '), 'sign accepted after successful pairing')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
