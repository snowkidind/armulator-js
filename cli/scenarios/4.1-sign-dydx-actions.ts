/**
 * 4.1 — sign-dydx-actions
 *
 * Verifies dYdX action types using EVM paths (coin type 60).
 * dYdX uses 0x addresses — same derived addresses as HL and on-chain operations.
 * One address per customer across all exchanges.
 *
 * Auth actions:
 *   AddAuthenticator, RemoveAuthenticator — any index, no destination
 *
 * Transfer actions:
 *   MsgTransfer, MsgSend — destination policy matches EVM transfer rules
 *     (0-49 → 50-99 only; 50+ → any internal)
 *
 * Withdrawal actions:
 *   MsgWithdrawFromSubaccount — internal pool OR external whitelist
 */
import { setup, teardown, assert, type ArmoryContext } from './_harness.js'
import { recoverAddress }                               from 'ethers'

const HASH          = '4'.repeat(64)
const DRAIN         = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
const SIG_RE        = /^[0-9a-fA-F]{130}$/

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup({ env: { ARMORY_DRAIN_ADDRESS: DRAIN } })

  const addr75  = (await ctx.client.send("derive m/44'/60'/0'/0/75")).slice(3)
  const addr10  = (await ctx.client.send("derive m/44'/60'/0'/0/10")).slice(3)
  const addr150 = (await ctx.client.send("derive m/44'/60'/0'/0/150")).slice(3)

  // ── Auth ──────────────────────────────────────────────────────────────────

  const r1 = await ctx.client.send(`sign m/44'/60'/0'/0/75 AddAuthenticator ${HASH}`)
  assert(r1.startsWith('ok '), 'AddAuthenticator: returns ok')
  assert(SIG_RE.test(r1.slice(3)), 'AddAuthenticator: signature is 65 bytes')

  const r2 = await ctx.client.send(`sign m/44'/60'/0'/0/150 RemoveAuthenticator ${HASH}`)
  assert(r2.startsWith('ok '), 'RemoveAuthenticator from user account: returns ok')

  // ── Transfer — staging tier applies ──────────────────────────────────────

  // MsgTransfer from 0-49: only 50-99 allowed
  const r3 = await ctx.client.send(`sign m/44'/60'/0'/0/5 MsgTransfer ${addr75} ${HASH}`)
  assert(r3.startsWith('ok '), 'MsgTransfer 0-49 → 50-99: allowed')

  const r4 = await ctx.client.send(`sign m/44'/60'/0'/0/5 MsgTransfer ${addr10} ${HASH}`)
  assert(r4 === 'err sign request denied', 'MsgTransfer 0-49 → 0-49: denied')

  const r5 = await ctx.client.send(`sign m/44'/60'/0'/0/5 MsgTransfer ${addr150} ${HASH}`)
  assert(r5 === 'err sign request denied', 'MsgTransfer 0-49 → 100+: denied')

  // MsgTransfer from 50+: any internal allowed
  const r6 = await ctx.client.send(`sign m/44'/60'/0'/0/75 MsgTransfer ${addr150} ${HASH}`)
  assert(r6.startsWith('ok '), 'MsgTransfer 50+ → 100+: allowed')

  // MsgSend (gas distribution) follows same transfer rules
  const r7 = await ctx.client.send(`sign m/44'/60'/0'/0/75 MsgSend ${addr10} ${HASH}`)
  assert(r7.startsWith('ok '), 'MsgSend 50+ → 0-49: allowed')

  // ── Withdrawal ────────────────────────────────────────────────────────────

  // MsgWithdrawFromSubaccount → internal address
  const r8 = await ctx.client.send(`sign m/44'/60'/0'/0/75 MsgWithdrawFromSubaccount ${addr150} ${HASH}`)
  assert(r8.startsWith('ok '), 'MsgWithdrawFromSubaccount → internal: allowed')

  // MsgWithdrawFromSubaccount → drain address
  const r9 = await ctx.client.send(`sign m/44'/60'/0'/0/75 MsgWithdrawFromSubaccount ${DRAIN} ${HASH}`)
  assert(r9.startsWith('ok '), 'MsgWithdrawFromSubaccount → drain: allowed')

  // MsgWithdrawFromSubaccount → non-whitelisted external: denied
  const r10 = await ctx.client.send(`sign m/44'/60'/0'/0/75 MsgWithdrawFromSubaccount 0x5555555555555555555555555555555555555555 ${HASH}`)
  assert(r10 === 'err sign request denied', 'MsgWithdrawFromSubaccount → non-whitelisted: denied')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
