/**
 * Mnemonic lifecycle: generate, import, encrypt, load.
 *
 * The mnemonic file lives at armory/.keys/mnemonic.enc.
 * It is encrypted with ARMORY_KEY using Argon2id + AES-256-CBC.
 *
 * Rules:
 *   - If mnemonic.enc does not exist and ARMORY_MNEMONIC is set → import phrase.
 *   - If mnemonic.enc does not exist and ARMORY_MNEMONIC is not set → generate phrase.
 *   - If mnemonic.enc exists → load and decrypt it; ARMORY_MNEMONIC is ignored.
 */
import { Mnemonic }         from 'ethers'
import crypto                from 'node:crypto'
import fs                    from 'node:fs'
import path                  from 'node:path'
import { fileURLToPath }     from 'node:url'
import { encrypt, decrypt }  from './encryption.js'
import { logger }            from './logger.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname  = path.dirname(__filename)

export const KEYS_DIR     = path.resolve(__dirname, '../.keys')
export const MNEMONIC_FILE = path.join(KEYS_DIR, 'mnemonic.enc')

// ── Error types ───────────────────────────────────────────────────────────────

/**
 * Thrown when the mnemonic cannot be established at all (invalid import phrase,
 * generation failure). The daemon should exit rather than run in error state.
 */
export class FatalMnemonicError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FatalMnemonicError'
  }
}

/**
 * Thrown when an existing mnemonic.enc cannot be decrypted or validated.
 * The daemon continues running but returns err on status.
 */
export class MnemonicLoadError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MnemonicLoadError'
  }
}

// ── Public entry point ────────────────────────────────────────────────────────

/**
 * Load the mnemonic from disk, or create it if it doesn't exist yet.
 * Returns the BIP-39 phrase as a string.
 *
 * Throws FatalMnemonicError  — invalid import phrase or generation failure (exit)
 * Throws MnemonicLoadError   — existing file can't be decrypted (run in error state)
 */
export async function loadOrInitMnemonic(armoryKey: string): Promise<string> {
  if (!fs.existsSync(MNEMONIC_FILE)) {
    const importPhrase = process.env.ARMORY_MNEMONIC
    if (importPhrase) {
      return importMnemonic(importPhrase, armoryKey)
    }
    return generateMnemonic(armoryKey)
  }
  return loadMnemonic(armoryKey)
}

// ── Private helpers ───────────────────────────────────────────────────────────

async function generateMnemonic(armoryKey: string): Promise<string> {
  const entropy = crypto.randomBytes(16)  // 128 bits → 12-word phrase
  const phrase  = Mnemonic.entropyToPhrase(entropy)
  await storeMnemonic(phrase, armoryKey)
  logger.info('mnemonic generated')
  return phrase
}

async function importMnemonic(phrase: string, armoryKey: string): Promise<string> {
  if (!Mnemonic.isValidMnemonic(phrase)) {
    throw new FatalMnemonicError('ARMORY_MNEMONIC is not a valid BIP-39 phrase')
  }
  await storeMnemonic(phrase, armoryKey)
  logger.info('mnemonic imported')
  return phrase
}

async function loadMnemonic(armoryKey: string): Promise<string> {
  const ciphertext = fs.readFileSync(MNEMONIC_FILE, 'utf8')
  let phrase: string
  try {
    phrase = await decrypt(ciphertext, armoryKey)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    throw new MnemonicLoadError(`failed to decrypt mnemonic: ${msg}`)
  }
  if (!Mnemonic.isValidMnemonic(phrase)) {
    throw new MnemonicLoadError('decrypted content is not a valid BIP-39 phrase')
  }
  logger.info('mnemonic loaded')
  return phrase
}

/**
 * Re-encrypt the mnemonic with a new key.
 * The armory must NOT be running when this is called.
 * On success the mnemonic and all derived addresses are unchanged —
 * only the at-rest encryption rotates.
 */
export async function rekeyMnemonic(oldKey: string, newKey: string): Promise<void> {
  if (!fs.existsSync(MNEMONIC_FILE)) {
    throw new Error('mnemonic.enc not found — nothing to rekey')
  }
  const ciphertext = fs.readFileSync(MNEMONIC_FILE, 'utf8')
  let phrase: string
  try {
    phrase = await decrypt(ciphertext, oldKey)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    throw new Error(`failed to decrypt mnemonic with current key: ${msg}`)
  }
  if (!Mnemonic.isValidMnemonic(phrase)) {
    throw new Error('decrypted content is not a valid BIP-39 phrase — refusing to rekey')
  }
  await storeMnemonic(phrase, newKey)
  logger.info('armory key rotated')
}

async function storeMnemonic(phrase: string, armoryKey: string): Promise<void> {
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 })
  }
  const ciphertext = await encrypt(phrase, armoryKey)
  fs.writeFileSync(MNEMONIC_FILE, ciphertext, { mode: 0o600 })
}
