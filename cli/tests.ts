import { spawn }           from 'node:child_process'
import { resolve, dirname } from 'node:path'
import { fileURLToPath }    from 'node:url'
import type { Interface }   from 'node:readline'
import { getAnswer }        from './common.js'

const __filename     = fileURLToPath(import.meta.url)
const __dirname      = dirname(__filename)
const SCENARIOS_DIR  = resolve(__dirname, 'scenarios')
const ARMORY_ROOT    = resolve(__dirname, '..')

interface Phase {
  num:       string
  label:     string
  scenarios: { key: string; label: string; file: string }[]
}

const PHASES: Phase[] = [
  {
    num:   '1',
    label: 'Foundation',
    scenarios: [
      { key: '1.1', label: 'init-keygen       — generates ARMORY_KEY, refuses to overwrite', file: '1.1-init-keygen.ts'      },
      { key: '1.2', label: 'startup-no-key    — exits with clear error when key absent',     file: '1.2-startup-no-key.ts'   },
      { key: '1.3', label: 'mnemonic-generate — init creates file, daemon loads without regenerating', file: '1.3-mnemonic-generate.ts' },
      { key: '1.4', label: 'mnemonic-import   — ARMORY_MNEMONIC imports; file wins after',  file: '1.4-mnemonic-import.ts'  },
      { key: '1.5', label: 'framing           — back-to-back frames, correct ordering',      file: '1.5-framing.ts'          },
      { key: '1.6', label: 'status            — ok ready / err mnemonic not loaded',         file: '1.6-status.ts'           },
    ],
  },
  {
    num:   '2',
    label: 'Derivation + Address Pool',
    scenarios: [
      { key: '2.1', label: 'derive-evm           — EVM address matches known test-mnemonic value', file: '2.1-derive-evm.ts'          },
      { key: '2.2', label: 'derive-cosmos        — cosmos1 bech32 address matches known value',    file: '2.2-derive-cosmos.ts'       },
      { key: '2.3', label: 'derive-deterministic — same paths after restart → identical addresses',file: '2.3-derive-deterministic.ts' },
      { key: '2.4', label: 'derive-invalid-path  — malformed paths → err invalid command',         file: '2.4-derive-invalid-path.ts'  },
      { key: '2.5', label: 'internal-pool        — all 100 EVM indices unique, correct format',    file: '2.5-internal-pool.ts'        },
    ],
  },
  {
    num:   '3',
    label: 'Signing + Destination Policy',
    scenarios: [
      { key: '3.1', label: 'sign-auth             — auth actions succeed any index, ecrecover matches', file: '3.1-sign-auth.ts'             },
      { key: '3.2', label: 'sign-whitelist-reject — unknown action types → err sign request denied',    file: '3.2-sign-whitelist-reject.ts'  },
      { key: '3.3', label: 'sign-transfer-staging — 0-49 can only transfer to 50-99',                  file: '3.3-sign-transfer-staging.ts'  },
      { key: '3.4', label: 'sign-transfer-high    — 50+ can transfer to any internal address',          file: '3.4-sign-transfer-high.ts'     },
      { key: '3.5', label: 'sign-withdrawal       — withdrawal to internal or whitelist; non-whitelist denied', file: '3.5-sign-withdrawal.ts'  },
      { key: '3.6', label: 'sign-withdraw-drain   — drain address whitelisted for any index',           file: '3.6-sign-withdraw-drain.ts'    },
      { key: '3.7', label: 'sign-uniform-errors   — all rejections return err sign request denied',     file: '3.7-sign-uniform-errors.ts'    },
      { key: '3.8', label: 'sign-hash-validation  — bad hash/dest format → err invalid command',        file: '3.8-sign-hash-validation.ts'   },
    ],
  },
  {
    num:   '4',
    label: 'dYdX Support',
    scenarios: [
      { key: '4.1', label: 'sign-dydx-actions — all dYdX action types, EVM paths, correct policy', file: '4.1-sign-dydx-actions.ts' },
    ],
  },
  {
    num:   '5',
    label: 'Hardening',
    scenarios: [
      { key: '5.1', label: 'pairing-handshake  — connect, pair, commands accepted',                file: '5.1-pairing-handshake.ts'  },
      { key: '5.2', label: 'pairing-failure    — wrong key → connection closed',                   file: '5.2-pairing-failure.ts'    },
      { key: '5.3', label: 'rate-limit         — >10 signs/sec → excess rejected',                 file: '5.3-rate-limit.ts'         },
      { key: '5.4', label: 'rekey              — ARMORY_KEY rotated, addresses unchanged',          file: '5.4-rekey.ts'              },
    ],
  },
]

function runScenario(file: string): Promise<number> {
  return new Promise(resolve => {
    const proc = spawn('npx', ['tsx', `${SCENARIOS_DIR}/${file}`], {
      stdio: 'inherit',
      cwd:   ARMORY_ROOT,
      env:   { ...process.env },
    })
    proc.on('close', code => resolve(code ?? 1))
  })
}

async function runPhase(phase: Phase): Promise<{ label: string; code: number }[]> {
  const results: { label: string; code: number }[] = []
  for (const s of phase.scenarios) {
    console.log(`\n  Running ${s.key}: ${s.label}\n`)
    const code = await runScenario(s.file)
    console.log(code === 0 ? '  PASS' : `  FAIL (exit ${code})`)
    results.push({ label: `${s.key} ${s.label}`, code })
  }
  return results
}

function printSummary(results: { label: string; code: number }[]): void {
  const pass = results.filter(r => r.code === 0).length
  const fail = results.filter(r => r.code !== 0).length
  console.log('\n  ── Results ──────────────────────────────────────────────────────')
  for (const r of results) {
    console.log(`  ${r.code === 0 ? 'PASS' : 'FAIL'}  ${r.label}`)
  }
  console.log(`\n  ${pass} passed  ${fail} failed`)
  console.log()
}

export async function testsMenu(rl: Interface): Promise<void> {
  const phaseLines = PHASES.map(p =>
    `  ${p.num.padEnd(4)} Phase ${p.num} — ${p.label}`,
  ).join('\n')

  const menu =
    '  ── Armory Tests ──────────────────────────────────────────\n' +
    phaseLines + '\n' +
    '  a    Run all\n' +
    '  b    Back'

  const answer = await getAnswer(rl, menu)
  if (answer === 'b' || !answer) return

  if (answer === 'a') {
    const allResults: { label: string; code: number }[] = []
    for (const phase of PHASES) {
      console.log(`\n  ── Phase ${phase.num}: ${phase.label} ──`)
      const results = await runPhase(phase)
      allResults.push(...results)
    }
    printSummary(allResults)
    return testsMenu(rl)
  }

  const phase = PHASES.find(p => p.num === answer)
  if (!phase) {
    console.log(`  Unknown option: ${answer}`)
    return testsMenu(rl)
  }

  console.log(`\n  ── Phase ${phase.num}: ${phase.label} ──`)
  const results = await runPhase(phase)
  printSummary(results)

  return testsMenu(rl)
}
