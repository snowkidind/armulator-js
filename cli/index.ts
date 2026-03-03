#!/usr/bin/env npx tsx
import { createInterface } from 'node:readline'
import { getAnswer }       from './common.js'
import { testsMenu }       from './tests.js'

const rl = createInterface({
  input:  process.stdin,
  output: process.stdout,
})

rl.on('close', () => process.exit(0))

async function mainMenu(): Promise<void> {
  const menu =
    '  ####### Armory CLI #######\n' +
    '  r    Run tests\n' +
    '  q    Exit'

  const answer = await getAnswer(rl, menu)

  if (answer === 'r') {
    await testsMenu(rl)
  } else if (answer === 'q') {
    console.log('  Exit.')
    rl.close()
    return
  }

  return mainMenu()
}

mainMenu().catch(err => {
  console.error('\n  Fatal:', err.message)
  process.exit(1)
})
