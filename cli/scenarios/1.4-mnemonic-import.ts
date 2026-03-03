/**
 * 1.4 — mnemonic-import
 *
 * Verifies:
 *   - When ARMORY_MNEMONIC is set and no mnemonic.enc exists, the phrase is imported
 *   - Subsequent run with ARMORY_MNEMONIC set still ignores it (file wins)
 *   - `status` returns `ok ready` after import
 *   - An invalid BIP-39 phrase causes the daemon to fail cleanly
 */
import fs   from 'node:fs'
import { setup, teardown, assert, KEYS_DIR, TEST_MNEMONIC, TEST_KEY, SOCKET_PATH, wipeKeys } from './_harness.js'
import net  from 'node:net'

const MNEMONIC_FILE = KEYS_DIR + '/mnemonic.enc'

try {
  // Run 1: import known phrase.
  const ctx1 = await setup()   // default opts use TEST_MNEMONIC
  assert(fs.existsSync(MNEMONIC_FILE), 'mnemonic.enc created from ARMORY_MNEMONIC')
  const stat1 = await ctx1.client.send('status')
  assert(stat1 === 'ok ready', 'status ok ready after import')
  await teardown(ctx1)

  // Run 2: mnemonic.enc already exists; ARMORY_MNEMONIC should be ignored.
  // Pass a DIFFERENT mnemonic — if the file wins, status is still ok ready.
  const ctx2 = await setup({ mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong' })
  const stat2 = await ctx2.client.send('status')
  assert(stat2 === 'ok ready', 'status ok ready (file wins over env var)')
  await teardown(ctx2)

  // Run 3: invalid BIP-39 phrase → daemon should not start (socket never opens).
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  const { startArmoryProcess, waitForSocket } = await import('./_harness.js')
  const proc = startArmoryProcess({ mnemonic: 'this is not a valid bip39 phrase at all ever' })
  let socketOpened = false
  try {
    await waitForSocket(SOCKET_PATH, 3_000)
    socketOpened = true
  } catch {
    // Expected — socket should not open.
  }
  proc.kill()
  assert(!socketOpened, 'invalid mnemonic prevents daemon from starting')

  console.log('\n  All assertions passed.\n')
  process.exit(0)
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  process.exit(1)
}
