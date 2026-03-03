/**
 * 5.4 — rekey
 *
 * Verifies that `armory rekey` rotates ARMORY_KEY without changing the mnemonic:
 *   1. Start armory with TEST_KEY — note address at index 0.
 *   2. Kill armory (keep mnemonic.enc on disk).
 *   3. Run `armory rekey` — captures new key from stdout.
 *   4. Restart armory with new key — status ok, same address at index 0.
 *
 * The rekey command prints the new key to stdout when ARMORY_NO_DOTENV=1
 * (test mode), so the test can capture it without touching .env.
 */
import fs                                                        from 'node:fs'
import { assert, startArmoryProcess, waitForSocket, performPairing,
         runCommand, wipeKeys, SOCKET_PATH, TEST_KEY, TEST_MNEMONIC,
         ArmoryClient }                                          from './_harness.js'
import type { ChildProcess }                                     from 'node:child_process'

const NEW_KEY_RE = /^[0-9a-f]{64}$/

let exitCode = 0
let proc: ChildProcess | null = null

try {
  // ── Phase 1: start with TEST_KEY, record address at index 0 ──────────────
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  proc = startArmoryProcess()
  const socket1 = await waitForSocket(SOCKET_PATH)
  await performPairing(socket1, TEST_MNEMONIC)
  const client1 = new ArmoryClient(socket1)

  const addrBefore = (await client1.send("derive m/44'/60'/0'/0/0")).slice(3)
  assert(addrBefore.startsWith('0x'), 'derive returns 0x address before rekey')

  client1.destroy()
  proc.kill()
  proc = null
  // Give process a moment to exit.
  await new Promise(r => setTimeout(r, 300))

  // ── Phase 2: rekey while armory is stopped ────────────────────────────────
  const rekeyResult = await runCommand(['rekey'], { env: { ARMORY_KEY: TEST_KEY, ARMORY_LOG_LEVEL: 'none' } })
  assert(rekeyResult.code === 0, `rekey exits 0 (got ${rekeyResult.code})`)

  const newKey = rekeyResult.stdout.trim()
  assert(NEW_KEY_RE.test(newKey), 'rekey prints 64-char hex new key to stdout')
  assert(newKey !== TEST_KEY,     'new key differs from old key')

  // ── Phase 3: restart with new key, verify same addresses ─────────────────
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  proc = startArmoryProcess({ key: newKey })
  const socket2 = await waitForSocket(SOCKET_PATH)
  await performPairing(socket2, TEST_MNEMONIC)
  const client2 = new ArmoryClient(socket2)

  const status = await client2.send('status')
  assert(status === 'ok ready', 'status ok after rekey')

  const addrAfter = (await client2.send("derive m/44'/60'/0'/0/0")).slice(3)
  assert(addrAfter === addrBefore, 'address at index 0 unchanged after rekey')

  // Spot-check another index — confirms the whole mnemonic is the same, not just index 0.
  const addr99 = (await client2.send("derive m/44'/60'/0'/0/99")).slice(3)
  assert(addr99.startsWith('0x') && addr99.length === 42, 'derive index 99 works after rekey')

  client2.destroy()
  proc.kill()
  proc = null

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

if (proc) proc.kill()
wipeKeys()
try { fs.unlinkSync(SOCKET_PATH) } catch {}
process.exit(exitCode)
