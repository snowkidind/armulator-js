/**
 * Wire protocol helpers — parse commands, format responses.
 *
 * Commands are UTF-8 text, whitespace-delimited.
 * Responses are either `ok <payload>` or `err <message>`.
 */

export interface ParsedCommand {
  cmd:  string
  args: string[]
}

export function parseCommand(raw: string): ParsedCommand {
  const parts = raw.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return { cmd: '', args: [] }
  return { cmd: parts[0], args: parts.slice(1) }
}

export function ok(payload: string): string {
  return `ok ${payload}`
}

export function err(message: string): string {
  return `err ${message}`
}
