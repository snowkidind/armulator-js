/**
 * 5.2 — pairing-failure
 *
 * Verifies that a client presenting the wrong pairing signature is rejected:
 *   - Armory sends nonce.
 *   - Client signs with a random key (not the mnemonic-derived key).
 *   - Armory closes the connection; no commands are accepted.
 *
 * This test bypasses the normal setup() flow and operates on raw socket
 * primitives to control the pairing signature independently.
 */
import fs                                                    from 'node:fs'
import { Wallet }                                            from 'ethers'
import { assert, startArmoryProcess, waitForSocket,
         readOneFrame, sendFrame, wipeKeys, SOCKET_PATH }    from './_harness.js'
import type { ChildProcess }                                 from 'node:child_process'

let exitCode = 0
let proc: ChildProcess | null = null

try {
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  proc = startArmoryProcess()

  const socket = await waitForSocket(SOCKET_PATH)

  // Read the nonce the armory sends on connect.
  const nonce = await readOneFrame(socket)
  assert(nonce.length === 64 && /^[0-9a-f]+$/i.test(nonce), 'nonce is 32 bytes hex')

  // Sign with a random key — NOT the correct pairing key derived from test mnemonic.
  const rogue = Wallet.createRandom()
  const sig   = rogue.signingKey.sign('0x' + nonce)
  const r     = sig.r.slice(2).padStart(64, '0')
  const s     = sig.s.slice(2).padStart(64, '0')
  const v     = sig.v.toString(16).padStart(2, '0')
  sendFrame(socket, r + s + v)

  // Armory should close the connection after verifying the bad signature.
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('socket not closed within 3 s')), 3_000)
    const done = (): void => { clearTimeout(timeout); resolve() }
    socket.once('close', done)
    socket.once('error', done)
  })

  assert(true, 'socket closed after bad pairing signature')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (proc) proc.kill()
wipeKeys()
try { fs.unlinkSync(SOCKET_PATH) } catch {}
process.exit(exitCode)
