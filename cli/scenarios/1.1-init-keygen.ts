/**
 * 1.1 — init-keygen
 *
 * Verifies:
 *   - `armory init` generates a 32-byte (64 hex char) ARMORY_KEY in .env
 *   - Running `armory init` again refuses to overwrite the existing entry
 */
import fs   from 'node:fs'
import path from 'node:path'
import { assert, runCommand, wipeKeys, ARMORY_ROOT } from './_harness.js'

const ENV_PATH = path.join(ARMORY_ROOT, '.env')

// ── Helpers ───────────────────────────────────────────────────────────────────

function readKey(): string | undefined {
  if (!fs.existsSync(ENV_PATH)) return undefined
  const match = fs.readFileSync(ENV_PATH, 'utf8').match(/^ARMORY_KEY=(.+)$/m)
  return match?.[1]?.trim()
}

function clearKey(): void {
  if (!fs.existsSync(ENV_PATH)) return
  const contents = fs.readFileSync(ENV_PATH, 'utf8')
  const updated  = contents.replace(/^ARMORY_KEY=.*\n?/m, '')
  if (updated.trim() === '') {
    fs.unlinkSync(ENV_PATH)
  } else {
    fs.writeFileSync(ENV_PATH, updated)
  }
}

// ── Test ──────────────────────────────────────────────────────────────────────

// process.exit() does not run finally blocks in Node.js — always call clearKey()
// explicitly before any exit path.
let exitCode = 0
try {
  // Ensure no ARMORY_KEY in .env and no leftover .keys/ before we start.
  clearKey()
  wipeKeys()

  // First run — should generate a key.
  const r1 = await runCommand(['init'])
  assert(r1.code === 0, 'init exits 0 on first run')

  const key = readKey()
  assert(typeof key === 'string', '.env contains ARMORY_KEY after init')
  assert(/^[0-9a-f]{64}$/.test(key ?? ''), 'ARMORY_KEY is 64 lowercase hex chars')
  assert(r1.stdout.includes('generated'), 'stdout confirms key generated')

  // Second run — should refuse.
  const r2 = await runCommand(['init'])
  assert(r2.code !== 0, 'init exits non-zero when ARMORY_KEY already set')
  assert(r2.stderr.includes('refusing'), 'stderr explains refusal')

  // Verify the key was NOT changed.
  const keyAfter = readKey()
  assert(keyAfter === key, 'ARMORY_KEY unchanged after refused second init')

  console.log('\n  All assertions passed.\n')
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  exitCode = 1
}

// Cleanup always runs — remove the test-generated key and mnemonic, restore pre-test state.
clearKey()
wipeKeys()
process.exit(exitCode)
