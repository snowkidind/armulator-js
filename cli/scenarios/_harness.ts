/**
 * Shared test harness for the armory scenario suite.
 *
 * Handles:
 *   - Armory process lifecycle (kill, wipe .keys/, start, wait for socket)
 *   - Length-prefixed IPC client (send/receive over /tmp/armory-test.sock)
 *   - Assertion helpers (assert)
 *
 * Convention:
 *   All scenarios use ARMORY_NO_DOTENV=1 so that a developer's local .env
 *   cannot contaminate the test environment; every required env var is passed
 *   explicitly to the subprocess. That includes EXTERNAL_WHITELIST_ADDRESS_01,
 *   which policy.ts requires at load — the harness injects a bogus test address
 *   (TEST_WHITELIST_ADDRESS) so the daemon starts without reading .env.
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
import { HDNodeWallet, Transaction, type TransactionLike } from 'ethers'

// ── Paths ─────────────────────────────────────────────────────────────────────

const __filename   = fileURLToPath(import.meta.url)
const __dirname    = path.dirname(__filename)
export const ARMORY_ROOT = path.resolve(__dirname, '../..')
export const KEYS_DIR    = '/tmp/armory-test-keys'   // isolated from production .keys/
export const ENV_PATH    = '/tmp/armory-test.env'    // isolated from production .env
export const SOCKET_PATH = '/tmp/armory-test.sock'   // isolated from production /tmp/armory.sock

// ── Test constants ────────────────────────────────────────────────────────────

export const TEST_KEY      = 'a'.repeat(64)   // 32 bytes, hex — fixed test key
export const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

// Bogus EVM address injected as EXTERNAL_WHITELIST_ADDRESS_01 so policy.ts can
// load under ARMORY_NO_DOTENV=1 (which skips .env, where the real value lives).
// Lowercase valid hex so ethers isAddress accepts it without a checksum. This is
// NOT a real whitelist entry — scenarios that assert on the active whitelist set
// ARMORY_EXTERNAL_WHITELIST instead.
export const TEST_WHITELIST_ADDRESS = '0x000000000000000000000000000000000000dead'

// Log the bogus-whitelist injection once per harness process so test output
// makes plain that a fake whitelist address is in use, never a real one.
let whitelistInjectionLogged = false
function logTestWhitelist(value: string): void {
  if (whitelistInjectionLogged) return
  console.error(`[harness] EXTERNAL_WHITELIST_ADDRESS_01=${value} (bogus test address; not a real whitelist)`)
  whitelistInjectionLogged = true
}

// Canonical path used for the pairing challenge-response handshake.
// Must match PAIRING_PATH in src/index.ts.
const PAIRING_PATH = "m/44'/60'/1'/0/0"

// ── Sign-request helpers (destination-binding protocol) ───────────────────────
//
// Wire form:  sign <signingPath> <actionType> <base64url(requestJSON)>
//   requestJSON = { artifact, destination? }
//   artifact    = { kind:'evm-tx', unsignedTx } | { kind:'hl-action', action }
// Response:   ok <derivedAddress> <signature130hex>
//
// `destination` is an OPTIONAL cross-check hint; omit it (undefined) to send no
// hint, or pass a string to exercise the defense-in-depth hint/bytes agreement.

export function encodeRequest(req: unknown): string {
  return Buffer.from(JSON.stringify(req), 'utf8').toString('base64url')
}

/** Serialize an unsigned EVM tx and wrap it as an evm-tx request token. */
export function evmToken(txRequest: TransactionLike, destination?: string | null): string {
  const unsignedTx = Transaction.from(txRequest).unsignedSerialized
  const req: Record<string, unknown> = { artifact: { kind: 'evm-tx', unsignedTx } }
  if (destination !== undefined) req.destination = destination
  return encodeRequest(req)
}

/** The 64-char unsigned-hash (no 0x) of an EVM tx — for positive-path ecrecover. */
export function evmUnsignedHash(txRequest: TransactionLike): string {
  return Transaction.from(txRequest).unsignedHash.slice(2)
}

/** Wrap an HL action object as an hl-action request token. */
export function hlToken(action: Record<string, unknown>, destination?: string | null): string {
  const req: Record<string, unknown> = { artifact: { kind: 'hl-action', action } }
  if (destination !== undefined) req.destination = destination
  return encodeRequest(req)
}

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
  try { fs.unlinkSync(ENV_PATH) } catch {}
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
    ARMORY_KEYS_DIR:    KEYS_DIR,
    ARMORY_ENV_PATH:    ENV_PATH,
    EXTERNAL_WHITELIST_ADDRESS_01: TEST_WHITELIST_ADDRESS,
    ...env,
  }
  logTestWhitelist(childEnv['EXTERNAL_WHITELIST_ADDRESS_01'])

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
      ARMORY_KEYS_DIR:  KEYS_DIR,
      ARMORY_ENV_PATH:  ENV_PATH,
      EXTERNAL_WHITELIST_ADDRESS_01: TEST_WHITELIST_ADDRESS,
      ...opts.env,
    }
    logTestWhitelist(childEnv['EXTERNAL_WHITELIST_ADDRESS_01'])

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
