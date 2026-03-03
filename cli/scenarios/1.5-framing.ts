/**
 * 1.5 — framing
 *
 * Verifies that the length-prefixed framing handles:
 *   - Multiple commands sent in rapid succession without waiting between them
 *   - Back-to-back frames arriving in a single TCP chunk
 *   - All responses arriving in the correct order with correct content
 */
import net  from 'node:net'
import { setup, teardown, assert, SOCKET_PATH,
         performPairing, TEST_MNEMONIC }         from './_harness.js'

const N = 20   // number of back-to-back commands

function sendRaw(socket: net.Socket, cmd: string): void {
  const payload = Buffer.from(cmd, 'utf8')
  const header  = Buffer.alloc(4)
  header.writeUInt32BE(payload.length, 0)
  socket.write(Buffer.concat([header, payload]))
}

function receiveAll(socket: net.Socket, count: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const responses: string[] = []
    let buffer = Buffer.alloc(0)

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk])
      while (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0)
        if (buffer.length < 4 + len) break
        const payload = buffer.slice(4, 4 + len).toString('utf8')
        buffer        = buffer.slice(4 + len)
        responses.push(payload)
        if (responses.length === count) resolve(responses)
      }
    })

    socket.on('error', reject)
    setTimeout(() => reject(new Error('timeout waiting for responses')), 10_000)
  })
}

try {
  const ctx = await setup()

  // Open a raw socket (bypassing ArmoryClient) to fire all commands at once.
  const rawSocket = await new Promise<net.Socket>((resolve, reject) => {
    const s = net.createConnection(SOCKET_PATH)
    s.once('connect', () => resolve(s))
    s.once('error',   reject)
  })

  // Every new connection requires the pairing handshake.
  await performPairing(rawSocket, TEST_MNEMONIC)

  // Fire N status commands without waiting for responses.
  for (let i = 0; i < N; i++) {
    sendRaw(rawSocket, 'status')
  }

  // Collect all N responses.
  const responses = await receiveAll(rawSocket, N)
  rawSocket.destroy()

  assert(responses.length === N, `received all ${N} responses`)
  for (let i = 0; i < N; i++) {
    assert(responses[i] === 'ok ready', `response ${i + 1} is ok ready`)
  }

  await teardown(ctx)

  console.log('\n  All assertions passed.\n')
  process.exit(0)
} catch (e) {
  console.error('\n  Test failed:', e instanceof Error ? e.message : e)
  process.exit(1)
}
