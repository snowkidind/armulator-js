// Thin shim — run the TypeScript CLI via tsx.
// Usage: node cli
import { spawn } from 'node:child_process'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dir = dirname(fileURLToPath(import.meta.url))
const child = spawn('npx', ['tsx', `${__dir}/cli/index.ts`], {
  stdio: 'inherit',
  cwd: __dir,
})
child.on('close', code => process.exit(code ?? 0))
