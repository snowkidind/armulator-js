/**
 * Shared test harness for armory Phase 1–5 scenarios.
 *
 * Handles:
 *   - Armory process lifecycle (kill, wipe .keys/, start, wait for socket)
 *   - Length-prefixed IPC client (send/receive over /tmp/armory.sock)
 *   - Assertion helpers (assert)
 *
 * Convention:
 *   All scenarios use ARMORY_NO_DOTENV=1 so that a developer's local .env
 *   cannot contaminate the test environment. All required env vars are passed
 *   explicitly to the subprocess.
 *
 * Test mnemonic (widely used BIP-39 test vector — all-abandon):
 *   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *
 * Usage in a scenario file:
 *   import { setup, teardown, assert } from './_harness.js'
 *   const ctx = await setup()
 *   assert(await ctx.send('status') === 'ok ready', 'status ok')
 *   await teardown(ctx)
 */
import net                      from 'node:net'
import fs                       from 'node:fs'
import path                     from 'node:path'
import { fileURLToPath }        from 'node:url'
import { spawn, ChildProcess }  from 'node:child_process'
import { HDNodeWallet }         from 'ethers'

// ── Paths ─────────────────────────────────────────────────────────────────────

const __filename   = fileURLToPath(import.meta.url)
const __dirname    = path.dirname(__filename)
export const ARMORY_ROOT = path.resolve(__dirname, '../..')
export const KEYS_DIR    = path.join(ARMORY_ROOT, '.keys')
export const ENV_PATH    = path.join(ARMORY_ROOT, '.env')
export const SOCKET_PATH = '/tmp/armory.sock'

// ── Test constants ────────────────────────────────────────────────────────────

export const TEST_KEY      = 'a'.repeat(64)   // 32 bytes, hex — fixed test key
export const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

// Canonical path used for the pairing challenge-response handshake.
// Must match PAIRING_PATH in src/index.ts.
const PAIRING_PATH = "m/44'/60'/0'/0/255"

// ── Assertion ─────────────────────────────────────────────────────────────────

export function assert(condition: boolean, label: string): void {
  if (condition) {
    console.log(`  PASS  ${label}`)
  } else {
    console.error(`  FAIL  ${label}`)
    throw new Error(`Assertion failed: ${label}`)
  }
}

// ── IPC client ────────────────────────────────────────────────────────────────

export class ArmoryClient {
  private buffer  = Buffer.alloc(0)
  private pending: Array<(response: string) => void> = []

  constructor(private socket: net.Socket) {
    socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      this.drain()
    })
  }

  private drain(): void {
    while (this.buffer.length >= 4) {
      const len = this.buffer.readUInt32BE(0)
      if (this.buffer.length < 4 + len) break
      const payload  = this.buffer.slice(4, 4 + len).toString('utf8')
      this.buffer    = this.buffer.slice(4 + len)
      const resolve  = this.pending.shift()
      if (resolve) resolve(payload)
    }
  }

  send(cmd: string): Promise<string> {
    return new Promise(resolve => {
      this.pending.push(resolve)
      const payload = Buffer.from(cmd, 'utf8')
      const header  = Buffer.alloc(4)
      header.writeUInt32BE(payload.length, 0)
      this.socket.write(Buffer.concat([header, payload]))
    })
  }

  destroy(): void {
    this.socket.destroy()
  }
}

// ── Low-level frame helpers (exported for pairing failure tests) ──────────────

/**
 * Read one length-prefixed frame from a raw socket.
 * Attaches a temporary data listener; removes it after the frame is received.
 */
export function readOneFrame(socket: net.Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0)
        if (buffer.length >= 4 + len) {
          socket.removeListener('data', onData)
          resolve(buffer.slice(4, 4 + len).toString('utf8'))
        }
      }
    }
    socket.on('data', onData)
    socket.once('error', reject)
    socket.once('close', () => reject(new Error('socket closed before frame received')))
  })
}

/** Write one length-prefixed frame to a raw socket. */
export function sendFrame(socket: net.Socket, payload: string): void {
  const bytes = Buffer.from(payload, 'utf8')
  const hdr   = Buffer.alloc(4)
  hdr.writeUInt32BE(bytes.length, 0)
  socket.write(Buffer.concat([hdr, bytes]))
}

/**
 * Perform the pairing handshake on a raw connected socket.
 * Reads the nonce sent by the armory, signs it with the key at PAIRING_PATH
 * derived from the given mnemonic, and sends back the signature.
 */
export async function performPairing(socket: net.Socket, mnemonic: string): Promise<void> {
  const nonce  = await readOneFrame(socket)
  const wallet = HDNodeWallet.fromPhrase(mnemonic, '', PAIRING_PATH)
  const sig    = wallet.signingKey.sign('0x' + nonce)
  const r      = sig.r.slice(2).padStart(64, '0')
  const s      = sig.s.slice(2).padStart(64, '0')
  const v      = sig.v.toString(16).padStart(2, '0')
  sendFrame(socket, r + s + v)
  // Server sends no response for successful pairing — proceed to commands.
}

// ── Lifecycle helpers ─────────────────────────────────────────────────────────

export interface ArmoryContext {
  proc:   ChildProcess
  client: ArmoryClient
}

export interface StartOptions {
  /** ARMORY_KEY to inject. Pass empty string to test missing-key behaviour. */
  key?:      string
  mnemonic?: string
  logLevel?: string
  /** Extra env vars to merge in. */
  env?:      Record<string, string>
}

export function wipeKeys(): void {
  if (fs.existsSync(KEYS_DIR)) {
    fs.rmSync(KEYS_DIR, { recursive: true, force: true })
  }
}

export function startArmoryProcess(opts: StartOptions = {}): ChildProcess {
  const {
    key      = TEST_KEY,
    mnemonic = TEST_MNEMONIC,
    logLevel = 'none',
    env      = {},
  } = opts

  const childEnv: Record<string, string> = {
    ...process.env as Record<string, string>,
    ARMORY_NO_DOTENV:   '1',
    ARMORY_LOG_LEVEL:   logLevel,
    ARMORY_SOCKET_PATH: SOCKET_PATH,
    ARMORY_POOL_SIZE:   '200',   // enough for system (0–99) + user accounts in tests
    ...env,
  }

  // Only inject key/mnemonic if they're non-empty.
  if (key)      childEnv['ARMORY_KEY']      = key
  if (mnemonic) childEnv['ARMORY_MNEMONIC'] = mnemonic

  const proc = spawn('npx', ['tsx', 'src/index.ts'], {
    cwd:   ARMORY_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env:   childEnv,
  })

  proc.stdout?.pipe(process.stdout)
  proc.stderr?.pipe(process.stderr)

  return proc
}

export async function waitForSocket(
  socketPath: string,
  maxWaitMs = 10_000,
): Promise<net.Socket> {
  const deadline = Date.now() + maxWaitMs
  while (Date.now() < deadline) {
    try {
      return await new Promise<net.Socket>((resolve, reject) => {
        const socket = net.createConnection(socketPath)
        socket.once('connect', () => resolve(socket))
        socket.once('error',   reject)
      })
    } catch {
      await new Promise(r => setTimeout(r, 200))
    }
  }
  throw new Error(`Armory socket not ready after ${maxWaitMs}ms`)
}

export async function setup(opts: StartOptions = {}): Promise<ArmoryContext> {
  // Kill any leftover armory from a previous run.
  try {
    const existing = net.createConnection(SOCKET_PATH)
    existing.destroy()
  } catch {}

  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}

  const proc     = startArmoryProcess(opts)
  const socket   = await waitForSocket(SOCKET_PATH)

  // Perform the pairing handshake before handing the socket to ArmoryClient.
  // Use || not ?? so that mnemonic:'' (random-generate tests) falls back to TEST_MNEMONIC.
  const mnemonic = opts.mnemonic || TEST_MNEMONIC
  await performPairing(socket, mnemonic)

  const client = new ArmoryClient(socket)
  return { proc, client }
}

export async function teardown(ctx: ArmoryContext): Promise<void> {
  ctx.client.destroy()
  ctx.proc.kill()
  wipeKeys()
  try { fs.unlinkSync(SOCKET_PATH) } catch {}
  // Give the process a moment to exit cleanly.
  await new Promise(r => setTimeout(r, 100))
}

// ── Subprocess helper (for init / rekey tests) ────────────────────────────────

export interface RunResult {
  code:   number
  stdout: string
  stderr: string
}

export function runCommand(
  args: string[],
  opts: { env?: Record<string, string> } = {},
): Promise<RunResult> {
  return new Promise(resolve => {
    const childEnv: Record<string, string> = {
      ...process.env as Record<string, string>,
      ARMORY_NO_DOTENV: '1',
      ...opts.env,
    }

    const proc = spawn('npx', ['tsx', 'src/index.ts', ...args], {
      cwd:   ARMORY_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env:   childEnv,
    })

    let stdout = ''
    let stderr = ''
    proc.stdout?.on('data', (c: Buffer) => { stdout += c.toString() })
    proc.stderr?.on('data', (c: Buffer) => { stderr += c.toString() })
    proc.on('close', code => resolve({ code: code ?? 1, stdout, stderr }))
  })
}
