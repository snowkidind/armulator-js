/**
 * Argon2id + AES-256-CBC symmetric encryption.
 *
 * Same pattern as tradeserv/src/keys/encryption.ts.
 *
 * Encryption flow:
 *   1. Generate 16-byte random salt
 *   2. Argon2id derives 48 bytes: first 32 = AES key, last 16 = IV
 *   3. AES-256-CBC encrypts the plaintext
 *   4. Output: base64( "Salted__" + salt + ciphertext )
 *
 * Decryption reverses: extract salt, re-derive key/IV, AES-CBC decrypt.
 */
import crypto from 'node:crypto'
import argon2  from 'argon2'

const SALT_LEN    = 16
const KEY_LEN     = 32   // AES-256
const IV_LEN      = 16   // AES block size
const HASH_LEN    = KEY_LEN + IV_LEN  // 48 bytes total
const MAGIC       = 'Salted__'
const MAGIC_BYTES = Buffer.from(MAGIC, 'utf8')  // 8 bytes

export async function encrypt(plaintext: string, password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_LEN)

  const derived = await argon2.hash(password + salt.toString('hex'), {
    type:       argon2.argon2id,
    hashLength: HASH_LEN,
    raw:        true,
    salt,
  })

  const key = derived.slice(0, KEY_LEN)
  const iv  = derived.slice(KEY_LEN, KEY_LEN + IV_LEN)

  const cipher    = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])

  const output = Buffer.concat([MAGIC_BYTES, salt, encrypted])
  return output.toString('base64')
}

export async function decrypt(ciphertext: string, password: string): Promise<string> {
  const raw = Buffer.from(ciphertext, 'base64')

  const magic = raw.slice(0, MAGIC_BYTES.length)
  if (!magic.equals(MAGIC_BYTES)) {
    throw new Error('decrypt: invalid format (missing Salted__ prefix)')
  }

  const salt      = raw.slice(MAGIC_BYTES.length, MAGIC_BYTES.length + SALT_LEN)
  const encrypted = raw.slice(MAGIC_BYTES.length + SALT_LEN)

  const derived = await argon2.hash(password + salt.toString('hex'), {
    type:       argon2.argon2id,
    hashLength: HASH_LEN,
    raw:        true,
    salt,
  })

  const key = derived.slice(0, KEY_LEN)
  const iv  = derived.slice(KEY_LEN, KEY_LEN + IV_LEN)

  const decipher  = crypto.createDecipheriv('aes-256-cbc', key, iv)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
  return decrypted.toString('utf8')
}
