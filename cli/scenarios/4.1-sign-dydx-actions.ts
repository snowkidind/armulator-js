/**
 * 4.1 — sign-dydx-actions  (Cosmos/dYdX binding not implemented yet)
 *
 * armory recomputes the signing hash from the artifact and extracts the recipient
 * from those bytes. The dYdX/Cosmos recompute + recipient extractor is not
 * implemented yet: its descriptors are SCAFFOLDED in src/actions.ts (artifactKind
 * 'cosmos-msg') but FAIL CLOSED.
 *
 * Every dYdX/Cosmos action must refuse to sign rather than blindly sign a caller
 * digest. This test pins that contract: all dYdX/Cosmos actions → denied.
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
