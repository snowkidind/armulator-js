/**
 * 1.2 — startup-no-key
 *
 * Verifies:
 *   - Armory exits immediately with a non-zero code when ARMORY_KEY is absent
 *   - Error message is clear and user-actionable
 */
import { assert, runCommand, wipeKeys } from './_harness.js'

try {
  wipeKeys()

  // Spawn daemon with no ARMORY_KEY in env (and ARMORY_NO_DOTENV=1 prevents
  // .env from loading it).
  const r = await runCommand([], { env: {} })  // no key injected

  assert(r.code !== 0,                             'exits non-zero when ARMORY_KEY absent')
  assert(r.stderr.includes('ARMORY_KEY'),          'error mentions ARMORY_KEY')
  assert(r.stderr.toLowerCase().includes('init') || r.stderr.toLowerCase().includes('set'),
    'error is actionable (mentions how to fix)')

  console.log('\n  All assertions passed.\n')
  process.exit(0)
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  process.exit(1)
} finally {
  wipeKeys()
}
