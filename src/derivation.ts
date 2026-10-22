/**
 * BIP-32/BIP-44 derivation and address encoding.
 *
 * Coin type determines address format:
 *   60  → EVM secp256k1 → keccak256(pubkey)[12:]  → EIP-55 checksummed hex (0x...)
 *   118 → Cosmos secp256k1 → ripemd160(sha256(pubkey)) → bech32 (cosmos1...)
 *
 * The bech32 prefix for coin 118 is `cosmos1`. dYdX (Phase 4) will introduce
 * its own coin type with prefix `dydx1`.
 */
import { HDNodeWallet }  from 'ethers'
import crypto             from 'node:crypto'
import { bech32 }         from 'bech32'

// ── Path validation ───────────────────────────────────────────────────────────

// Valid BIP-32 path: m/ followed by one or more segments of digits + optional '
const PATH_RE = /^m(\/\d+'?)+$/

export function isValidPath(path: string): boolean {
  return PATH_RE.test(path)
}

// Extract coin type from BIP-44 path (m/44'/<coin>'/...).
// Returns null if the path is not a BIP-44 path.
export function coinType(path: string): number | null {
  const m = path.match(/^m\/44'\/(\d+)'/)
  return m ? parseInt(m[1], 10) : null
}

// Extract the account index — the final numeric segment of the path.
export function pathIndex(path: string): number {
  const parts = path.split('/')
  return parseInt(parts[parts.length - 1].replace("'", ''), 10)
}

// ── Address derivation ────────────────────────────────────────────────────────

/**
 * Derive an address from a mnemonic and BIP-32 path.
 * Throws if the path is invalid or the coin type is unsupported.
 */
export function deriveAddress(mnemonic: string, path: string): string {
  if (!isValidPath(path)) throw new Error('invalid BIP-32 path')

  const coin = coinType(path)
  if (coin === 60)  return deriveEvm(mnemonic, path)
  if (coin === 118) return deriveCosmos(mnemonic, path, 'cosmos1')
  throw new Error(`unsupported coin type: ${coin}`)
}

/** EVM address: keccak256(pubkey)[12:] as EIP-55 checksummed hex. */
function deriveEvm(mnemonic: string, path: string): string {
  const wallet = HDNodeWallet.fromPhrase(mnemonic, '', path)
  return wallet.address   // ethers returns EIP-55 checksummed
}

/** Cosmos-family address: ripemd160(sha256(compressedPubkey)) as bech32. */
function deriveCosmos(mnemonic: string, path: string, prefix: string): string {
  const wallet     = HDNodeWallet.fromPhrase(mnemonic, '', path)
  const pubkeyBytes = Buffer.from(wallet.publicKey.slice(2), 'hex') // drop 0x
  const sha256Hash  = crypto.createHash('sha256').update(pubkeyBytes).digest()
  const hash        = crypto.createHash('ripemd160').update(sha256Hash).digest()
  return bech32.encode(prefix, bech32.toWords(hash))
}

// ── Internal address pool ─────────────────────────────────────────────────────

export interface AddressPool {
  /** EVM addresses indexed by derivation index (EIP-55 checksummed). */
  evm: string[]
  /** Cosmos addresses indexed by derivation index (cosmos1 prefix). */
  cosmos: string[]
  /** Lowercase EVM address → derivation index, for O(1) membership + tier check. */
  evmIndexMap: Map<string, number>
  /** Cosmos address → derivation index, for O(1) membership + tier check. */
  cosmosIndexMap: Map<string, number>
}

/**
 * Number of addresses derived per batch. Initial pool and each expansion
 * are always a multiple of this value.
 */
const POOL_BATCH_SIZE = 125

/**
 * Expand an existing pool in-place to cover at least minSize indices.
 * Always expands to the next POOL_BATCH_SIZE boundary so expansions are
 * amortised — a request for index 126 grows the pool to 250, not 127.
 */
export function expandPool(pool: AddressPool, mnemonic: string, minSize: number): void {
  const newSize = Math.ceil(minSize / POOL_BATCH_SIZE) * POOL_BATCH_SIZE
  for (let i = pool.evm.length; i < newSize; i++) {
    const evmAddr    = deriveEvm(mnemonic,    `m/44'/60'/0'/0/${i}`)
    const cosmosAddr = deriveCosmos(mnemonic, `m/44'/118'/0'/0/${i}`, 'cosmos1')
    pool.evm.push(evmAddr)
    pool.cosmos.push(cosmosAddr)
    pool.evmIndexMap.set(evmAddr.toLowerCase(), i)
    pool.cosmosIndexMap.set(cosmosAddr, i)
  }
}

/**
 * Derive and cache the internal address pool at startup.
 * Size is configurable via ARMORY_POOL_SIZE (covers system accounts 0–99 and
 * user accounts 100+).
 *
 * EVM:    m/44'/60'/0'/0/0  …  m/44'/60'/0'/0/<size-1>
 * Cosmos: m/44'/118'/0'/0/0 …  m/44'/118'/0'/0/<size-1>
 */
export function buildAddressPool(mnemonic: string, size: number): AddressPool {
  const evm:    string[] = []
  const cosmos: string[] = []

  for (let i = 0; i < size; i++) {
    evm.push(deriveEvm(mnemonic,    `m/44'/60'/0'/0/${i}`))
    cosmos.push(deriveCosmos(mnemonic, `m/44'/118'/0'/0/${i}`, 'cosmos1'))
  }

  const evmIndexMap    = new Map<string, number>()
  const cosmosIndexMap = new Map<string, number>()
  for (let i = 0; i < size; i++) {
    evmIndexMap.set(evm[i].toLowerCase(), i)
    cosmosIndexMap.set(cosmos[i], i)
  }

  return { evm, cosmos, evmIndexMap, cosmosIndexMap }
}
