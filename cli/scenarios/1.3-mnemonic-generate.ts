/**
 * 1.3 — mnemonic-generate
 *
 * Verifies:
 *   - `armory init` creates mnemonic.enc when none exists (random generation)
 *   - Daemon starts successfully and loads the mnemonic (does not regenerate)
 *   - Second daemon restart loads the same mnemonic (content unchanged)
 *
 * Because init generates a RANDOM mnemonic (ARMORY_MNEMONIC not set),
 * the harness cannot perform the pairing handshake (it doesn't know the
 * mnemonic). Instead we verify daemon startup by receiving the nonce the
 * armory sends on connect — the nonce is only emitted after the socket server
 * starts, which only happens after the mnemonic is loaded.
 *
 * "Daemon does not regenerate" is verified by comparing mnemonic.enc bytes
 * across both daemon runs — each generation uses a new random salt, so
 * identical bytes prove the file was loaded, not regenerated.
 */
import fs                                                       from 'node:fs'
import path                                                     from 'node:path'
import { assert, runCommand, startArmoryProcess, waitForSocket, readOneFrame,
         wipeKeys, SOCKET_PATH, KEYS_DIR, ENV_PATH }           from './_harness.js'
import type { ChildProcess }                                     from 'node:child_process'

const MNEMONIC_FILE = KEYS_DIR + '/mnemonic.enc'

let exitCode = 0
let proc: ChildProcess | null = null

try {
  // ── init: generate random key + mnemonic ─────────────────────────────────────
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}
  // Remove any existing ARMORY_KEY from .env so init can write a fresh one.
  if (fs.existsSync(ENV_PATH)) {
    const contents = fs.readFileSync(ENV_PATH, 'utf8')
    const updated  = contents.replace(/^ARMORY_KEY=.*\n?/m, '')
    updated.trim() === '' ? fs.unlinkSync(ENV_PATH) : fs.writeFileSync(ENV_PATH, updated)
  }

  const initResult = await runCommand(['init'], { env: { ARMORY_LOG_LEVEL: 'none' } })
  assert(initResult.code === 0, 'init exits 0')
  assert(fs.existsSync(MNEMONIC_FILE), 'mnemonic.enc created by init')

  // Read the key that init wrote to .env — the daemon must use the same key.
  const envContents = fs.readFileSync(ENV_PATH, 'utf8')
  const keyMatch    = envContents.match(/^ARMORY_KEY=([0-9a-f]{64})$/m)
  assert(keyMatch !== null, 'init wrote ARMORY_KEY to .env')
  const generatedKey = keyMatch![1]

  const enc1 = fs.readFileSync(MNEMONIC_FILE, 'utf8')

  // ── First daemon run ──────────────────────────────────────────────────────────
  proc = startArmoryProcess({ key: generatedKey, mnemonic: '' })  // no ARMORY_MNEMONIC — must load from file

  const socket1 = await waitForSocket(SOCKET_PATH)
  // The armory sends a nonce immediately on connect. Receiving it proves the
  // server is up, which means the mnemonic was loaded (not regenerated).
  const nonce1 = await readOneFrame(socket1)
  socket1.destroy()

  assert(nonce1.length === 64, 'armory sent 32-byte nonce (startup complete, first daemon run)')

  proc.kill()
  proc = null
  await new Promise(r => setTimeout(r, 300))

  // ── Second daemon run ─────────────────────────────────────────────────────────
  proc = startArmoryProcess({ key: generatedKey, mnemonic: '' })

  const socket2 = await waitForSocket(SOCKET_PATH)
  const nonce2  = await readOneFrame(socket2)
  socket2.destroy()

  assert(nonce2.length === 64, 'armory sent 32-byte nonce (startup complete, second daemon run)')

  const enc2 = fs.readFileSync(MNEMONIC_FILE, 'utf8')
  assert(enc1 === enc2, 'mnemonic.enc unchanged across daemon restarts (loaded, not regenerated)')

  proc.kill()
  proc = null

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (proc) proc.kill()
wipeKeys()
// Restore .env: remove the test-generated key.
if (fs.existsSync(ENV_PATH)) {
  const contents = fs.readFileSync(ENV_PATH, 'utf8')
  const updated  = contents.replace(/^ARMORY_KEY=.*\n?/m, '')
  if (updated.trim() === '') { try { fs.unlinkSync(ENV_PATH) } catch {} }
  else fs.writeFileSync(ENV_PATH, updated)
}
try { fs.unlinkSync(SOCKET_PATH) } catch {}
process.exit(exitCode)
