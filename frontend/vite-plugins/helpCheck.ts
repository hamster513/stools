// Vite-плагин: перед сборкой прогоняет ту же проверку справки, что и `npm run check:help`.
// Сборка падает с перечнем ошибок «файл: текст». coverage — проверять ли покрытие routes.json.

import type { Plugin } from 'vite'
import { checkHelp } from '../scripts/check-help.ts'

export function helpCheck({ coverage }: { coverage: boolean }): Plugin {
  let root = process.cwd()
  return {
    name: 'stools-help-check',
    configResolved(config) {
      root = config.root
    },
    buildStart() {
      const messages = checkHelp(root, coverage)
      if (messages.length > 0) throw new Error(messages.join('\n'))
    },
  }
}
