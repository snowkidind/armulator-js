/**
 * EVM artifact recompute + recipient extraction (destination-binding fix #5).
 *
 * Ported from phaselive/hotsign/src/authz/chainRules/evm.ts (`extractRecipient`,
 * native `to` / ERC-20 `transfer(address,uint256)` calldata). Local port, not a
 * cross-service import.
 *
 * Two independent operations over the SAME unsigned-tx bytes armory will sign:
 *   1. recomputeEvmHash  — `Transaction.from(unsignedTx).unsignedHash`. The caller
 *      cannot supply a divergent digest; the bytes inspected == the bytes signed.
 *      Rejects an already-signed tx (fail loud).
 *   2. extractEvmRecipient — the TRUE recipient: native `to`, or the ERC-20
 *      `transfer` recipient hidden in calldata. FAILS CLOSED (returns null) on any
 *      shape it does not recognize — a decode gap refuses the sign, never guesses.
 */
import { getAddress, Transaction } from 'ethers'
import type { Recipient } from '../actions.js'

const TRANSFER = '0xa9059cbb'  // transfer(address,uint256)

// The first 32-byte ABI arg holds a right-aligned 20-byte address: hex chars [34,74) after 0x.
function argAddress(data: string): string {
  return getAddress('0x' + data.slice(34, 74))
}

/**
 * Recompute the signing hash from the unsigned tx. Returns the 64-char hex digest
 * (no 0x prefix). Throws on an undecodable or already-signed transaction.
 */
export function recomputeEvmHash(unsignedTx: string): string {
  let parsed: Transaction
  try {
    parsed = Transaction.from(unsignedTx)
  } catch {
    throw new Error('evm artifact undecodable')
  }
  if (parsed.signature) throw new Error('evm artifact is already signed')
  return parsed.unsignedHash.slice(2)
}

/**
 * Decode the true recipient from the unsigned tx bytes. Returns null (fail closed)
 * on any unrecognized shape — the caller must then deny the sign.
 */
export function extractEvmRecipient(unsignedTx: string): Recipient | null {
  let parsed: Transaction
  try {
    parsed = Transaction.from(unsignedTx)
  } catch {
    return null
  }
  try {
    const to   = parsed.to
    const data = parsed.data ?? '0x'
    if (data === '0x') {
      // native transfer: recipient is `to`. No `to` (contract creation) → none.
      return to ? { kind: 'transfer', recipient: getAddress(to) } : { kind: 'none' }
    }
    const selector = data.slice(0, 10).toLowerCase()
    if (selector === TRANSFER) {
      return { kind: 'transfer', recipient: argAddress(data) }  // ERC-20 recipient bound
    }
    // Any other calldata (approve, swaps, arbitrary contract calls) is not a
    // fund-move armory authorizes on the transfer/withdrawal path → fail closed.
    return null
  } catch {
    return null
  }
}
