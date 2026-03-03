/**
 * ARMORY_LOG_LEVEL-gated log wrapper.
 *
 * All log calls in the codebase must go through this module.
 * Never call console.log / console.error directly.
 *
 * Levels:
 *   debug — full output (command lifecycle, startup events, rejection reasons)
 *   info  — startup events and rejections only  (default)
 *   none  — no output; all calls are no-ops
 */

type LogLevel = 'debug' | 'info' | 'none'

function parseLevel(): LogLevel {
  const v = process.env.ARMORY_LOG_LEVEL?.toLowerCase()
  if (v === 'debug' || v === 'info' || v === 'none') return v
  return 'info'
}

const level = parseLevel()

// Returns true if the given minimum level is enabled.
function on(min: 'debug' | 'info'): boolean {
  if (level === 'none')  return false
  if (level === 'debug') return true
  return min === 'info'
}

/* eslint-disable @typescript-eslint/no-unused-vars */
export const logger = {
  debug: on('debug') ? (msg: string) => console.log(`[DEBUG] ${msg}`)  : (_: string) => {},
  info:  on('info')  ? (msg: string) => console.log(`[INFO]  ${msg}`)  : (_: string) => {},
  warn:  on('info')  ? (msg: string) => console.warn(`[WARN]  ${msg}`) : (_: string) => {},
  error: on('info')  ? (msg: string) => console.error(`[ERROR] ${msg}`) : (_: string) => {},
}
