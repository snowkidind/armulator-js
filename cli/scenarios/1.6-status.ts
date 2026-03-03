/**
 * 1.6 — status
 *
 * Verifies:
 *   - `status` returns `ok ready` after healthy startup
 *   - `status` returns `err mnemonic not loaded` when mnemonic.enc is corrupted
 */
import fs   from 'node:fs'
import { setup, teardown, assert, KEYS_DIR, wipeKeys, startArmoryProcess, waitForSocket,
         performPairing, TEST_MNEMONIC, ArmoryClient, SOCKET_PATH }                        from './_harness.js'

const MNEMONIC_FILE = KEYS_DIR + '/mnemonic.enc'

try {
  // Part A: healthy startup → ok ready
  const ctx = await setup()
  const r1  = await ctx.client.send('status')
  assert(r1 === 'ok ready', 'status returns ok ready after healthy startup')
  await teardown(ctx)

  // Part B: corrupted mnemonic.enc → err mnemonic not loaded
  // Write a corrupted mnemonic.enc directly — no need to run a healthy startup first.
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}
  fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(MNEMONIC_FILE, 'this is not valid encrypted content!!!', { mode: 0o600 })

  // Start armory with no ARMORY_MNEMONIC. mnemonic.enc exists (corrupted), so
  // the import path is skipped and load is attempted → fails → error state.
  // When mnemonic is null the armory accepts any pairing signature.
  const proc   = startArmoryProcess({ mnemonic: '' })
  const socket = await waitForSocket(SOCKET_PATH)
  await performPairing(socket, TEST_MNEMONIC)
  const client = new ArmoryClient(socket)

  const r2 = await client.send('status')
  assert(r2 === 'err mnemonic not loaded', 'status returns err mnemonic not loaded after corruption')

  client.destroy()
  proc.kill()
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  console.log('\n  All assertions passed.\n')
  process.exit(0)
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  process.exit(1)
}
