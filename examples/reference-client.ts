/**
 * Reference client for armory (armulator-js).
 *
 * A minimal, standalone example of a program that talks to the armory daemon
 * over its Unix socket. It deliberately does NOT import anything from `src/` —
 * it reimplements the wire protocol from scratch so you can read the whole
 * client in one file and port it to your own software.
 *
 * What it demonstrates, end to end:
 *   1. Connecting to the socket and completing the pairing handshake.
 *   2. The length-prefixed framing used for every message.
 *   3. A few commands: status, noop, derive, a permitted sign, a denied sign.
 *
 * Prerequisites — a daemon must already be running with a known pairing key:
 *
 *   npm run init          # prints HOTSERV_PAIRING_KEY=0x...  (copy it)
 *   npm start             # in another terminal
 *
 * Then run this client with the pairing key in the environment:
 *
 *   ARMORY_PAIRING_KEY=0x...  npm run example
 *   # (HOTSERV_PAIRING_KEY is also accepted, matching the reference daemon)
 *
 * The pairing key is the PRIVATE key at m/44'/60'/0'/0/255, derived from the
 * same mnemonic the daemon holds. A real client only ever needs this key — not
 * the mnemonic. See README → "Connecting your software".
 */
import net    from 'node:net'
import { Wallet, Transaction, parseEther, parseUnits } from 'ethers'

const SOCKET_PATH = process.env.ARMORY_SOCKET_PATH ?? '/tmp/armory.sock'

// Fail loud if the pairing key is missing — no silent fallback. Without it we
// cannot complete the handshake, and a default key would only mask the mistake.
const PAIRING_KEY = process.env.ARMORY_PAIRING_KEY ?? process.env.HOTSERV_PAIRING_KEY
if (!PAIRING_KEY) {
  console.error(
    'No pairing key set. Export ARMORY_PAIRING_KEY (or HOTSERV_PAIRING_KEY) —\n' +
    'the private key printed by `npm run init` as HOTSERV_PAIRING_KEY=0x...',
  )
  process.exit(1)
}

// ── Wire protocol: 4-byte big-endian length prefix + UTF-8 payload ─────────────

function frame(payload: string): Buffer {
  const bytes = Buffer.from(payload, 'utf8')
  const header = Buffer.alloc(4)
  header.writeUInt32BE(bytes.length, 0)
  return Buffer.concat([header, bytes])
}

/**
 * A tiny framed-message client. One in-flight request at a time (the armory
 * answers commands in order), which is all a simple caller needs.
 */
class Client {
  private buffer = Buffer.alloc(0)
  private waiters: Array<(frame: string) => void> = []

  constructor(private socket: net.Socket) {
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      while (this.buffer.length >= 4) {
        const len = this.buffer.readUInt32BE(0)
        if (this.buffer.length < 4 + len) break
        const payload = this.buffer.subarray(4, 4 + len).toString('utf8')
        this.buffer = this.buffer.subarray(4 + len)
        this.waiters.shift()?.(payload)
      }
    })
  }

  /** Wait for the next inbound frame (used for the pairing nonce). */
  nextFrame(): Promise<string> {
    return new Promise((resolve) => this.waiters.push(resolve))
  }

  /** Send a command and resolve with the daemon's reply (`ok ...` / `err ...`). */
  send(cmd: string): Promise<string> {
    const reply = this.nextFrame()
    this.socket.write(frame(cmd))
    return reply
  }

  close(): void {
    this.socket.destroy()
  }
}

// ── Pairing handshake ──────────────────────────────────────────────────────────

/**
 * The daemon sends a 32-byte random nonce (as 64 hex chars) the instant we
 * connect. We sign those bytes with the pairing key and send back the 65-byte
 * signature (130 hex chars): r(32) || s(32) || v(1). The daemon recovers the
 * signer and checks it matches the mnemonic's pairing address. On success it
 * sends nothing — the next frame we receive is the reply to our first command.
 */
function signNonce(nonceHex: string): string {
  const wallet = new Wallet(PAIRING_KEY!)
  const sig = wallet.signingKey.sign('0x' + nonceHex)
  const r = sig.r.slice(2).padStart(64, '0')
  const s = sig.s.slice(2).padStart(64, '0')
  const v = sig.v.toString(16).padStart(2, '0')
  return r + s + v
}

// ── Run ─────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const socket = net.createConnection(SOCKET_PATH)
  socket.on('error', (e) => {
    console.error(`socket error: ${e.message}\nIs the daemon running? (npm start, socket ${SOCKET_PATH})`)
    process.exit(1)
  })

  await new Promise<void>((resolve) => socket.once('connect', resolve))
  const client = new Client(socket)

  // 1. Pair: read the nonce frame, sign it, send the signature frame.
  const nonce = await client.nextFrame()
  socket.write(frame(signNonce(nonce)))
  console.log('paired\n')

  // 2. Liveness + status.
  console.log('status ->', await client.send('status'))   // ok ready
  console.log('noop   ->', await client.send('noop'))      // ok alive

  // 3. Derive addresses from the internal pool. Index 60 (tier 50–99) is a valid
  //    transfer target for a staging signer (index 5, tier 0–49).
  console.log('derive ->', await client.send("derive m/44'/60'/0'/0/0"))
  const dest = (await client.send("derive m/44'/60'/0'/0/60")).slice(3)

  // 4. A PERMITTED sign. The wire form sends the UNSIGNED artifact, not a
  //    digest: armory recomputes the signing hash from it and decodes the true
  //    recipient from the same bytes. Here, a native EVM transfer to an internal
  //    address. The reply is `ok <derivedSignerAddress> <signature130hex>` — a
  //    real client MUST assert that address equals the expected signer before it
  //    broadcasts anything.
  const unsignedTx = Transaction.from({
    to: dest, value: parseEther('0.01'), chainId: 42161, nonce: 0,
    gasLimit: 21000n, maxFeePerGas: parseUnits('0.1', 'gwei'),
    maxPriorityFeePerGas: parseUnits('0.1', 'gwei'), type: 2,
  }).unsignedSerialized
  const req = (artifact: unknown) => Buffer.from(JSON.stringify({ artifact }), 'utf8').toString('base64url')
  const transferToken = req({ kind: 'evm-tx', unsignedTx })
  console.log('sign   ->', await client.send(`sign m/44'/60'/0'/0/5 transfer ${transferToken}`))

  // 5. A DENIED sign — an action type that isn't in the registry. The policy
  //    answers with a uniform `err sign request denied` (it never says why).
  console.log('denied ->', await client.send(`sign m/44'/60'/0'/0/5 notARealAction ${transferToken}`))

  client.close()
}

main().catch((e) => {
  console.error('Fatal:', e instanceof Error ? e.message : String(e))
  process.exit(1)
})
