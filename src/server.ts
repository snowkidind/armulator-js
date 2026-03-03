/**
 * Unix socket server with 4-byte big-endian length-prefix framing.
 *
 * Frame format: [uint32 BE payload length][payload bytes (UTF-8)]
 *
 * Connection lifecycle:
 *   1. Server sends a 32-byte random nonce (framed) immediately on connect.
 *   2. Client signs the nonce with the canonical pairing key (m/44'/60'/0'/0/255)
 *      and returns the 65-byte signature (framed).
 *   3. Server calls verifyPairing(nonce, sig). Mismatch → connection closed.
 *   4. Normal command dispatch begins. Sign commands are rate-limited to
 *      RATE_LIMIT_MAX_SIGNS per RATE_LIMIT_WINDOW_MS per connection.
 */
import crypto  from 'node:crypto'
import net     from 'node:net'
import fs      from 'node:fs'
import { logger } from './logger.js'

const HEADER_BYTES         = 4
const RATE_LIMIT_WINDOW_MS = 1_000
const RATE_LIMIT_MAX_SIGNS = 10

export function startServer(
  socketPath:    string,
  verifyPairing: (nonce: string, sig: string) => boolean,
  dispatch:      (cmd: string) => Promise<string>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    try { fs.unlinkSync(socketPath) } catch {}

    const server = net.createServer(handleConnection(verifyPairing, dispatch))

    server.on('error', reject)
    server.listen(socketPath, () => {
      logger.info(`listening on ${socketPath}`)
      resolve()
    })
  })
}

// ── Connection handler factory ────────────────────────────────────────────────

function handleConnection(
  verifyPairing: (nonce: string, sig: string) => boolean,
  dispatch:      (cmd: string) => Promise<string>,
) {
  return (socket: net.Socket): void => {
    logger.debug('client connected')

    let buffer     = Buffer.alloc(0)
    let paired     = false
    let processing = false
    const signTimes: number[] = []  // sliding window for rate limiting

    // Send challenge nonce immediately on connect.
    const nonce      = crypto.randomBytes(32).toString('hex')
    const nonceBytes = Buffer.from(nonce, 'utf8')
    const nonceHdr   = Buffer.alloc(HEADER_BYTES)
    nonceHdr.writeUInt32BE(nonceBytes.length, 0)
    socket.write(Buffer.concat([nonceHdr, nonceBytes]))

    const sendFrame = (msg: string): void => {
      const bytes = Buffer.from(msg, 'utf8')
      const hdr   = Buffer.alloc(HEADER_BYTES)
      hdr.writeUInt32BE(bytes.length, 0)
      socket.write(Buffer.concat([hdr, bytes]))
    }

    const processBuffer = async (): Promise<void> => {
      if (processing) return
      processing = true

      while (buffer.length >= HEADER_BYTES) {
        const payloadLen = buffer.readUInt32BE(0)
        if (buffer.length < HEADER_BYTES + payloadLen) break

        const payload = buffer.slice(HEADER_BYTES, HEADER_BYTES + payloadLen).toString('utf8')
        buffer        = buffer.slice(HEADER_BYTES + payloadLen)

        if (!paired) {
          if (!verifyPairing(nonce, payload)) {
            logger.debug('pairing failed — closing connection')
            socket.destroy()
            processing = false
            return
          }
          paired = true
          logger.debug('connection paired')
          continue  // no response sent for successful pairing
        }

        // Rate limit sign commands.
        if (payload.startsWith('sign ')) {
          const now = Date.now()
          while (signTimes.length && signTimes[0] < now - RATE_LIMIT_WINDOW_MS) {
            signTimes.shift()
          }
          if (signTimes.length >= RATE_LIMIT_MAX_SIGNS) {
            sendFrame('err rate limit exceeded')
            continue
          }
          signTimes.push(now)
        }

        const response = await dispatch(payload)
        sendFrame(response)
      }

      processing = false
      if (buffer.length >= HEADER_BYTES) processBuffer()
    }

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk])
      processBuffer()
    })

    socket.on('error', (e) => logger.debug(`socket error: ${e.message}`))
    socket.on('close', ()  => logger.debug('client disconnected'))
  }
}
