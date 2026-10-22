/**
 * Hyperliquid EIP-712 typed-data — LOCAL COPY (armory-owned, authoritative).
 *
 * Armory recomputes the signing hash itself from the action the caller hands
 * over (destination-binding fix #5): it must therefore own the schemas rather
 * than trust a caller-supplied digest. Per project convention this is a LOCAL
 * copy, never a cross-service import.
 *
 * Source of the schemas copied verbatim below:
 *   hotserv/src/exchanges/adapters/src/hl/hashing.ts
 *     — USER_ACTION_DOMAIN_ARBITRUM, ApproveAgent, UserSetAbstraction,
 *       UsdClassTransfer, Withdraw (copied field-for-field).
 *
 * UsdSend / SpotSend: hashing.ts documents them as user-action schemes
 *   (its header + the "User-action signing (approveAgent, usdSend, withdraw3,
 *   spotSend)" section) but ships no typed-data builder for them — the current
 *   hotserv builder hashes usdSend via the phantom-agent scheme. They are added
 *   here from the canonical Hyperliquid SDK user-action schema so the bound
 *   recompute has an authoritative definition. See DEVIATIONS note at bottom.
 *
 * This module is pure: no I/O, no key custody, no signing. It only recomputes a
 * 32-byte EIP-712 digest from an action object. Every builder picks the EXACT
 * fields its schema declares and FAILS LOUD on a missing/malformed field — that
 * is what binds the digest to the claimed action type (an action of the wrong
 * shape cannot produce a valid digest, closing actionType-spoofing).
 */
import { encode } from '@msgpack/msgpack'
import { ethers } from 'ethers'

// ── Phantom-agent scheme (source:'c') — used by `deposit` ──────────────────────
//
// `deposit` is signed with HL's phantom-agent EIP-712 scheme (NOT the user-action
// scheme above), with source='c' (chain-signed) and no vault. This is the exact
// scheme the committed hotserv hasher uses: `buildTypedDataHash(action, nonce, false)`
// in hotserv/src/exchanges/adapters/src/hl/hashing.ts (ported verbatim below so
// armory is authoritative over the bytes it signs — LOCAL COPY, no cross-service
// import, per project convention).
//
//   connectionId = keccak256( msgpack(action) || nonce_uint64_be || vaultFlag )
//   hash         = EIP-712 over { name:'Exchange', version:'1', chainId:1337,
//                                 verifyingContract:0x0 }, type Agent{source,connectionId}
// No vault → vaultFlag is the single byte 0x00.

const PHANTOM_DOMAIN: ethers.TypedDataDomain = {
  name:              'Exchange',
  version:           '1',
  chainId:           1337,
  verifyingContract: '0x0000000000000000000000000000000000000000',
}

const AGENT_TYPES = {
  Agent: [
    { name: 'source',       type: 'string'  },
    { name: 'connectionId', type: 'bytes32' },
  ],
}

/**
 * Build the 32-byte connectionId (phantom-agent scheme), no vault.
 * connectionId = keccak256( msgpack(action) || nonce_uint64_be || 0x00 )
 * Ported byte-for-byte from hotserv hashing.ts `buildConnectionId` (no-vault path).
 */
function buildConnectionId(action: unknown, nonce: number | bigint): string {
  const actionBytes = encode(action)

  const nonceBuf = new Uint8Array(8)
  new DataView(nonceBuf.buffer).setBigUint64(0, BigInt(nonce), false)

  const vaultBuf = new Uint8Array([0x00])

  const combined = new Uint8Array(actionBytes.length + 8 + vaultBuf.length)
  combined.set(actionBytes, 0)
  combined.set(nonceBuf,    actionBytes.length)
  combined.set(vaultBuf,    actionBytes.length + 8)

  return ethers.keccak256(combined)
}

// ── User-action domain (we always sign HL user actions on Arbitrum) ────────────

const ARBITRUM_CHAIN_ID = 42161

const USER_ACTION_DOMAIN_ARBITRUM: ethers.TypedDataDomain = {
  name:              'HyperliquidSignTransaction',
  version:           '1',
  chainId:           ARBITRUM_CHAIN_ID,
  verifyingContract: '0x0000000000000000000000000000000000000000',
}

// ── Typed-data schemas (copied from hashing.ts; UsdSend/SpotSend added) ────────

const APPROVE_AGENT_TYPES = {
  'HyperliquidTransaction:ApproveAgent': [
    { name: 'hyperliquidChain', type: 'string'  },
    { name: 'agentAddress',     type: 'address' },
    { name: 'agentName',        type: 'string'  },
    { name: 'nonce',            type: 'uint64'  },
  ],
}

const USER_SET_ABSTRACTION_TYPES = {
  'HyperliquidTransaction:UserSetAbstraction': [
    { name: 'hyperliquidChain', type: 'string'  },
    { name: 'user',             type: 'address' },
    { name: 'abstraction',      type: 'string'  },
    { name: 'nonce',            type: 'uint64'  },
  ],
}

const USD_CLASS_TRANSFER_TYPES = {
  'HyperliquidTransaction:UsdClassTransfer': [
    { name: 'hyperliquidChain', type: 'string' },
    { name: 'amount',           type: 'string' },
    { name: 'toPerp',           type: 'bool'   },
    { name: 'nonce',            type: 'uint64' },
  ],
}

const WITHDRAW3_TYPES = {
  'HyperliquidTransaction:Withdraw': [
    { name: 'hyperliquidChain', type: 'string' },
    { name: 'destination',      type: 'string' },
    { name: 'amount',           type: 'string' },
    { name: 'time',             type: 'uint64' },
  ],
}

const USD_SEND_TYPES = {
  'HyperliquidTransaction:UsdSend': [
    { name: 'hyperliquidChain', type: 'string' },
    { name: 'destination',      type: 'string' },
    { name: 'amount',           type: 'string' },
    { name: 'time',             type: 'uint64' },
  ],
}

const SPOT_SEND_TYPES = {
  'HyperliquidTransaction:SpotSend': [
    { name: 'hyperliquidChain', type: 'string' },
    { name: 'destination',      type: 'string' },
    { name: 'token',            type: 'string' },
    { name: 'amount',           type: 'string' },
    { name: 'time',             type: 'uint64' },
  ],
}

// ── Strict field pickers (FAIL LOUD — binds the digest to the action shape) ────

type Action = Record<string, unknown>

function reqString(action: Action, key: string): string {
  const v = action[key]
  if (typeof v !== 'string') throw new Error(`hl action missing string field '${key}'`)
  return v
}

// Address field: must be a string; lowercased to match hashing.ts normalization.
function reqAddress(action: Action, key: string): string {
  return reqString(action, key).toLowerCase()
}

// uint64 field: accept a JS number or a decimal-digit string (ethers accepts both).
function reqUint(action: Action, key: string): number | bigint {
  const v = action[key]
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v
  if (typeof v === 'string' && /^\d+$/.test(v)) return BigInt(v)
  throw new Error(`hl action missing uint64 field '${key}'`)
}

function reqBool(action: Action, key: string): boolean {
  const v = action[key]
  if (typeof v !== 'boolean') throw new Error(`hl action missing bool field '${key}'`)
  return v
}

// ── Recompute functions — return the 64-char hex digest (no 0x prefix) ─────────

function hash(types: Record<string, { name: string; type: string }[]>, value: Record<string, unknown>): string {
  return ethers.TypedDataEncoder.hash(USER_ACTION_DOMAIN_ARBITRUM, types, value).slice(2)
}

export function hashApproveAgent(action: Action): string {
  return hash(APPROVE_AGENT_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    agentAddress:     reqAddress(action, 'agentAddress'),
    agentName:        reqString(action, 'agentName'),  // may be '' (revoke) — still required
    nonce:            reqUint(action, 'nonce'),
  })
}

export function hashUserSetAbstraction(action: Action): string {
  return hash(USER_SET_ABSTRACTION_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    user:             reqAddress(action, 'user'),
    abstraction:      reqString(action, 'abstraction'),
    nonce:            reqUint(action, 'nonce'),
  })
}

export function hashUsdClassTransfer(action: Action): string {
  return hash(USD_CLASS_TRANSFER_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    amount:           reqString(action, 'amount'),
    toPerp:           reqBool(action, 'toPerp'),
    nonce:            reqUint(action, 'nonce'),
  })
}

export function hashWithdraw3(action: Action): string {
  return hash(WITHDRAW3_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    destination:      reqAddress(action, 'destination'),
    amount:           reqString(action, 'amount'),
    time:             reqUint(action, 'time'),
  })
}

export function hashUsdSend(action: Action): string {
  return hash(USD_SEND_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    destination:      reqAddress(action, 'destination'),
    amount:           reqString(action, 'amount'),
    time:             reqUint(action, 'time'),
  })
}

export function hashSpotSend(action: Action): string {
  return hash(SPOT_SEND_TYPES, {
    hyperliquidChain: reqString(action, 'hyperliquidChain'),
    destination:      reqAddress(action, 'destination'),
    token:            reqString(action, 'token'),
    amount:           reqString(action, 'amount'),
    time:             reqUint(action, 'time'),
  })
}

// ── deposit — phantom-agent source:'c' scheme (NOT user-action) ────────────────

/**
 * Recompute the `deposit` signing hash. Unlike the six user-signed actions,
 * `deposit` uses HL's phantom-agent EIP-712 scheme with source='c' and no vault
 * — byte-identical to the committed hotserv hasher `buildTypedDataHash(action,
 * nonce, false)`. The whole `action` object (as the caller built it) is
 * msgpack-encoded; the nonce is taken from `action.nonce`. category `auth`,
 * no external recipient.
 *
 * FAILS LOUD on a missing/non-uint `nonce` (binds the hash to a well-formed
 * deposit action). Returns the 64-char hex digest (no 0x prefix), matching the
 * convention of the user-action hashers above.
 */
export function hashDeposit(action: Action): string {
  const nonce        = reqUint(action, 'nonce')
  const connectionId = buildConnectionId(action, nonce)
  return ethers.TypedDataEncoder
    .hash(PHANTOM_DOMAIN, AGENT_TYPES, { source: 'c', connectionId })
    .slice(2)
}

// ── Recipient field accessors (the true recipient lives in the typed struct) ───

/** withdraw3 / usdSend recipient. Throws if absent — caller treats as fail-closed. */
export function recipientDestination(action: Action): string {
  return reqString(action, 'destination')
}

/*
 * DEVIATIONS from the plan's "copy from hashing.ts" instruction:
 *  - UsdSend / SpotSend are NOT present as typed-data builders in hashing.ts
 *    (only named in its comments); reconstructed here from the canonical HL SDK
 *    user-action schema. usdSend/spotSend carry a destination that MUST be bound,
 *    so an authoritative schema is required.
 *  - `deposit` does NOT use the user-action scheme. It uses HL's phantom-agent
 *    EIP-712 scheme with source='c' (see `hashDeposit` above), byte-identical to
 *    hotserv's committed `buildTypedDataHash(action, nonce, false)`. armory now
 *    recomputes that same hash from the action (binding actionType='deposit' to the
 *    signed bytes) — it is LIVE, not fail-closed. This required adding the
 *    @msgpack/msgpack dependency (the phantom-agent connectionId msgpacks the
 *    action); that is a genuine need of the deposit scheme, not an optional knob.
 */
