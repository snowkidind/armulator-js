/**
 * 4.1 — sign-dydx-actions  (deferred: Cosmos/dYdX binding is a later phase)
 *
 * The destination-binding fix makes armory recompute the signing hash from the
 * artifact and extract the recipient from those bytes. The dYdX/Cosmos recompute
 * + recipient extractor is a later phase: its descriptors are SCAFFOLDED in
 * src/actions.ts (artifactKind 'cosmos-msg') but FAIL CLOSED today.
 *
 * Until that extractor lands, every dYdX/Cosmos action must refuse to sign rather
 * than fall back to blindly signing a caller digest (which was the #5 bug class).
 * This test pins that interim contract: all dYdX/Cosmos actions → denied.
 */
import { setup, teardown, assert, encodeRequest, type ArmoryContext } from './_harness.js'

// A well-formed cosmos-msg artifact so the request parses; the refusal must come
// from the not-yet-implemented recompute (fail closed), not malformed input.
const COSMOS_TOKEN = encodeRequest({ artifact: { kind: 'cosmos-msg', msg: { foo: 'bar' } } })

const DYDX_ACTIONS = [
  'registerAccount',
  'transferOut',
  'withdraw',
  'AddAuthenticator',
  'RemoveAuthenticator',
  'MsgTransfer',
  'MsgSend',
  'MsgWithdrawFromSubaccount',
]

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  for (const action of DYDX_ACTIONS) {
    const r = await ctx.client.send(`sign m/44'/60'/0'/0/75 ${action} ${COSMOS_TOKEN}`)
    assert(r === 'err sign request denied', `${action}: fails closed (Cosmos binding deferred)`)
  }

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
