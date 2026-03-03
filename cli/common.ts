import type { Interface } from 'node:readline'

export function getAnswer(rl: Interface, prompt: string): Promise<string> {
  return new Promise(resolve => {
    rl.question('\n' + prompt + '\n> ', answer => resolve(answer.trim()))
  })
}
