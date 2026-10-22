/**
 * 3.11 — sign-deposit  (phantom-agent scheme, byte-provenance)
 *
 * `deposit` is the one action armory signs with HL's phantom-agent EIP-712 scheme
 * (source 'c', no vault) rather than the user-action scheme. It moves no external
 * funds (category auth), so there is no recipient to bind — instead this proves
 * armory signs the EXACT phantom-agent bytes HL expects.
 *
 * GOLDEN is computed independently by the canonical hasher
 * perpdex-adapters/src/hl/hashing.ts `buildTypedDataHash(DEPOSIT, nonce, false)`
 * (the port armory copies). The test signs the deposit through armory and checks
 * the returned signature recovers to the signer OVER that golden hash — so if
 * armory's hashDeposit ever drifts from the scheme, the recovered address stops
 * matching and this fails.
 *
 * NOTE: never broadcasts — only armory's accept + signature is asserted.
 */
import { setup, teardown, assert, hlToken, type ArmoryContext } from './_harness.js'
import { recoverAddress, getAddress }                           from 'ethers'

const SIGN_PATH = "m/44'/60'/0'/0/100"

// Fixed deposit action. Key order matches buildDeposit (src/hl/builder.ts) so the
// msgpack bytes — and therefore the hash — are deterministic across the wire
// round-trip (JSON preserves insertion order, armory msgpacks what it parses).
const DEPOSIT = { type: 'deposit', hyperliquidChain: 'Mainnet', amount: '5', nonce: 1700000000000 }

// Independently computed: perpdex-adapters buildTypedDataHash(DEPOSIT, nonce, false).
const GOLDEN = '0x1df3231da63938c159f1ae9c4f4fc5b5d6491497fe81acd3c2eabf31f404fd3e'

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup()

  const signer = getAddress((await ctx.client.send(`derive ${SIGN_PATH}`)).slice(3))

  // Positive path: a well-formed deposit signs.
  const reply = await ctx.client.send(`sign ${SIGN_PATH} deposit ${hlToken(DEPOSIT)}`)
  assert(reply.startsWith('ok '), `deposit signs (reply: ${reply})`)

  const [, addr, sig] = reply.split(' ')
  assert(getAddress(addr) === signer, 'reply address is the SIGN_PATH signer')

  // The crux: the signature must recover to the signer over the INDEPENDENT golden
  // hash — proving armory signed exactly the phantom-agent bytes, not some other digest.
  assert(getAddress(recoverAddress(GOLDEN, '0x' + sig)) === signer,
    'signature recovers to signer over the independent phantom-agent hash')

  // Changing the nonce changes the signed bytes, so recovery over GOLDEN no longer
  // yields the signer — confirms the hash is bound to the action, not fixed.
  const other  = { ...DEPOSIT, nonce: DEPOSIT.nonce + 1 }
  const reply2 = await ctx.client.send(`sign ${SIGN_PATH} deposit ${hlToken(other)}`)
  assert(reply2.startsWith('ok '), 'deposit with a different nonce still signs')
  const sig2 = reply2.split(' ')[2]
  assert(getAddress(recoverAddress(GOLDEN, '0x' + sig2)) !== signer,
    'different nonce → different hash (no longer recovers to signer over GOLDEN)')

  // Fail-closed: a deposit action missing its nonce cannot recompute → denied.
  const noNonce = { type: 'deposit', hyperliquidChain: 'Mainnet', amount: '5' }
  assert((await ctx.client.send(`sign ${SIGN_PATH} deposit ${hlToken(noNonce)}`)) === 'err sign request denied',
    'deposit missing nonce: denied (fail closed)')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
