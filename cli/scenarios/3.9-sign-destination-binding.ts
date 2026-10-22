/**
 * 3.9 — sign-destination-binding  (regression for issue #5)
 *
 * armory recomputes the hash from the unsigned tx and extracts the TRUE recipient
 * from those same bytes, so a caller cannot argue a whitelisted `destination` string
 * while handing over a hash that pays an attacker — the whitelist validates the
 * bytes, not a self-asserted label:
 *   - CONTROL (honest non-whitelisted recipient)            → err sign request denied
 *   - CASE A  (native tx → attacker, lies dest=whitelisted) → err sign request denied
 *   - CASE B  (ERC-20 calldata → attacker, lies dest=wl)    → err sign request denied
 *   - POSITIVE (honest whitelisted recipient)               → ok, sig recovers to the signer
 *
 * NOTE: never broadcasts — a signature is the whole vulnerability; we only assert
 * armory's accept/refuse decision.
 */
import { setup, teardown, assert, evmToken, evmUnsignedHash, type ArmoryContext } from './_harness.js'
import { recoverAddress, getAddress, parseEther, parseUnits }                     from 'ethers'

const WHITELISTED = getAddress('0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7') // the whitelisted destination the caller asserts
const ATTACKER    = getAddress('0xbadc0ffee0ddf00dbadc0ffee0ddf00dbadc0ffe') // where the money actually goes
const USDC        = getAddress('0xaf88d065e77c8cC2239327C5EDb3A432268e5831')
const SIGN_PATH   = "m/44'/60'/0'/0/100"
const FEE         = { chainId: 42161, gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 as const }

const nativeTx = (to: string, nonce: number) => ({ to, value: parseEther('0.25'), nonce, ...FEE })
const erc20Tx  = (to: string, nonce: number) => {
  const data = '0xa9059cbb' + to.slice(2).toLowerCase().padStart(64, '0') + (100_000_000n).toString(16).padStart(64, '0')
  return { to: USDC, value: 0, data, nonce, chainId: 42161, gasLimit: 120000n, maxFeePerGas: parseUnits('0.1', 'gwei'), maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2 as const }
}

let exitCode = 0
let ctx: ArmoryContext | null = null
try {
  ctx = await setup({ env: { ARMORY_EXTERNAL_WHITELIST: WHITELISTED } })

  // CONTROL — honest call to a non-whitelisted address is correctly refused.
  const control = await ctx.client.send(`sign ${SIGN_PATH} evmWithdraw ${evmToken(nativeTx(ATTACKER, 1), ATTACKER)}`)
  assert(control === 'err sign request denied', 'CONTROL honest non-whitelisted recipient: denied')

  // POSITIVE — honest withdrawal to the whitelisted address signs, and the sig
  // recovers over the recomputed hash to the derived signer at SIGN_PATH.
  const signerAddr = (await ctx.client.send(`derive ${SIGN_PATH}`)).slice(3)
  const posTx = nativeTx(WHITELISTED, 2)
  const pos = await ctx.client.send(`sign ${SIGN_PATH} evmWithdraw ${evmToken(posTx, WHITELISTED)}`)
  assert(pos.startsWith('ok '), 'POSITIVE honest whitelisted recipient: allowed')
  const [okAddr, okSig] = pos.slice(3).split(' ')
  assert(okAddr.toLowerCase() === signerAddr.toLowerCase(), 'POSITIVE: returned address is the signer at SIGN_PATH')
  const recovered = recoverAddress('0x' + evmUnsignedHash(posTx), '0x' + okSig)
  assert(recovered.toLowerCase() === signerAddr.toLowerCase(), 'POSITIVE: sig recovers over the RECOMPUTED tx hash to the signer')

  // CASE A — native tx pays the attacker, but the caller lies dest=whitelisted.
  const caseA = await ctx.client.send(`sign ${SIGN_PATH} evmWithdraw ${evmToken(nativeTx(ATTACKER, 7), WHITELISTED)}`)
  assert(caseA === 'err sign request denied', 'CASE A native→attacker (lies dest=whitelisted): denied [flipped from ok]')

  // CASE B — ERC-20 transfer: tx.to is the USDC contract, the real recipient is
  // in calldata. Caller again lies dest=whitelisted.
  const caseB = await ctx.client.send(`sign ${SIGN_PATH} evmWithdraw ${evmToken(erc20Tx(ATTACKER, 8), WHITELISTED)}`)
  assert(caseB === 'err sign request denied', 'CASE B erc20→attacker (recipient in calldata, lies dest=wl): denied [flipped from ok]')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (ctx) await teardown(ctx)
process.exit(exitCode)
