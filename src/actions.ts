/**
 * Action descriptor registry — the action-aware core of the destination-binding
 * fix (#5). One descriptor per whitelisted actionType:
 *
 *   { category, artifactKind, recomputeHash(artifact), extractRecipient(artifact) }
 *
 * Replaces the bare ACTION_WHITELIST map that used to live in signer.ts. The
 * `category` semantics (auth / internal / transfer / withdrawal) are unchanged;
 * what is new is that each descriptor knows how to (a) recompute the signing hash
 * from the artifact the caller hands over, and (b) decode the TRUE recipient from
 * those same bytes. armory therefore binds the policy decision to the exact bytes
 * it signs, instead of trusting a caller-supplied digest + destination string.
 *
 * armory is now action-aware (it owns the EVM tx decoder and the HL EIP-712
 * schemas). This is the deliberate reversal of the earlier "chain-agnostic
 * hash-signer" framing — the custody guarantee is worth it (see README).
 *
 * FAIL CLOSED: recomputeHash throws and extractRecipient returns null on any
 * undecodable / not-yet-implemented artifact. dYdX/Cosmos extractors are a later
 * phase — their descriptors are scaffolded here but fail closed today.
 */
import { recomputeEvmHash, extractEvmRecipient } from './evm/extract.js'
import * as hl from './hl/typedData.js'

export type ActionCategory = 'auth' | 'internal' | 'transfer' | 'withdrawal'

export type ArtifactKind = 'evm-tx' | 'hl-action' | 'cosmos-msg'

export type Artifact =
  | { kind: 'evm-tx';    unsignedTx: string }
  | { kind: 'hl-action'; action: Record<string, unknown> }
  | { kind: 'cosmos-msg'; [k: string]: unknown }

/** Decoded recipient from the signed bytes. `none` = the bytes move no funds to
 *  an external recipient (auth/internal actions). */
export type Recipient =
  | { kind: 'none' }
  | { kind: 'transfer'; recipient: string }

export interface ActionDescriptor {
  category:     ActionCategory
  artifactKind: ArtifactKind
  /** Recompute the signing hash from the artifact. Returns 64-char hex (no 0x).
   *  Throws on an undecodable artifact or one whose shape does not match the
   *  claimed action (closes actionType-spoofing). */
  recomputeHash:    (artifact: Artifact) => string
  /** Decode the true recipient from the same bytes. Returns null → fail closed. */
  extractRecipient: (artifact: Artifact) => Recipient | null
}

// ── Helpers to build descriptors ───────────────────────────────────────────────

function notYetImplemented(actionType: string): never {
  throw new Error(`action '${actionType}' has no bound recompute yet (fail closed)`)
}

// HL auth/internal: the schema carries no external recipient. The hash is still
// recomputed from the claimed action's schema, so a withdraw-shaped artifact
// submitted under an auth actionType fails to recompute (missing fields) → denied.
function hlNoRecipient(recompute: (a: Record<string, unknown>) => string): Omit<ActionDescriptor, 'category'> {
  return {
    artifactKind: 'hl-action',
    recomputeHash: (artifact) => {
      if (artifact.kind !== 'hl-action') throw new Error('expected hl-action artifact')
      return recompute(artifact.action)
    },
    extractRecipient: (artifact) =>
      artifact.kind === 'hl-action' ? { kind: 'none' } : null,
  }
}

// HL fund-move: recipient is a field inside the typed struct (withdraw3/usdSend/spotSend).
function hlWithRecipient(recompute: (a: Record<string, unknown>) => string): Omit<ActionDescriptor, 'category'> {
  return {
    artifactKind: 'hl-action',
    recomputeHash: (artifact) => {
      if (artifact.kind !== 'hl-action') throw new Error('expected hl-action artifact')
      return recompute(artifact.action)
    },
    extractRecipient: (artifact) => {
      if (artifact.kind !== 'hl-action') return null
      try {
        return { kind: 'transfer', recipient: hl.recipientDestination(artifact.action) }
      } catch {
        return null
      }
    },
  }
}

// Generic EVM tx (native / ERC-20). recipient decoded from the unsigned tx bytes.
const evmTx: Omit<ActionDescriptor, 'category'> = {
  artifactKind: 'evm-tx',
  recomputeHash: (artifact) => {
    if (artifact.kind !== 'evm-tx') throw new Error('expected evm-tx artifact')
    return recomputeEvmHash(artifact.unsignedTx)
  },
  extractRecipient: (artifact) =>
    artifact.kind === 'evm-tx' ? extractEvmRecipient(artifact.unsignedTx) : null,
}

// Cosmos / dYdX seam — scaffolded, fails closed until the recompute+extractor land.
function cosmosScaffold(actionType: string): Omit<ActionDescriptor, 'category'> {
  return {
    artifactKind: 'cosmos-msg',
    recomputeHash:    () => notYetImplemented(actionType),
    extractRecipient: () => null,
  }
}

// ── Registry ────────────────────────────────────────────────────────────────────

const REGISTRY = new Map<string, ActionDescriptor>()

function register(actionType: string, category: ActionCategory, base: Omit<ActionDescriptor, 'category'>): void {
  REGISTRY.set(actionType, { category, ...base })
}

// ── Hyperliquid (hl-action) ─────────────────────────────────────────────────────
register('approveAgent',       'auth',       hlNoRecipient(hl.hashApproveAgent))
register('userSetAbstraction', 'auth',       hlNoRecipient(hl.hashUserSetAbstraction))
register('usdClassTransfer',   'internal',   hlNoRecipient(hl.hashUsdClassTransfer))
register('usdSend',            'transfer',   hlWithRecipient(hl.hashUsdSend))
register('spotSend',           'transfer',   hlWithRecipient(hl.hashSpotSend))
register('withdraw3',          'withdrawal', hlWithRecipient(hl.hashWithdraw3))
// `deposit` is LIVE: phantom-agent source:'c' scheme (NOT user-action), category
// auth / no recipient. armory recomputes the same phantom-'c' hash hotserv's
// committed buildTypedDataHash(action, nonce, false) produces (see hl/typedData.ts
// hashDeposit). hlNoRecipient still binds actionType='deposit' to the signed bytes.
register('deposit',            'auth',       hlNoRecipient(hl.hashDeposit))

// ── Generic EVM on-chain (evm-tx) ────────────────────────────────────────────────
register('transfer',           'transfer',   evmTx)
register('evmWithdraw',        'withdrawal', evmTx)

// ── dYdX / Cosmos (cosmos-msg) — scaffolded, fail closed (later phase) ───────────
register('registerAccount',           'auth',       cosmosScaffold('registerAccount'))
register('transferOut',               'transfer',   cosmosScaffold('transferOut'))
register('withdraw',                  'withdrawal', cosmosScaffold('withdraw'))
register('AddAuthenticator',          'auth',       cosmosScaffold('AddAuthenticator'))
register('RemoveAuthenticator',       'auth',       cosmosScaffold('RemoveAuthenticator'))
register('MsgTransfer',               'transfer',   cosmosScaffold('MsgTransfer'))
register('MsgSend',                   'transfer',   cosmosScaffold('MsgSend'))
register('MsgWithdrawFromSubaccount', 'withdrawal', cosmosScaffold('MsgWithdrawFromSubaccount'))

// ── Lookups ───────────────────────────────────────────────────────────────────

export function getDescriptor(actionType: string): ActionDescriptor | null {
  return REGISTRY.get(actionType) ?? null
}

/** Back-compat accessor: the action's category, or null if not whitelisted. */
export function getCategory(actionType: string): ActionCategory | null {
  return REGISTRY.get(actionType)?.category ?? null
}
