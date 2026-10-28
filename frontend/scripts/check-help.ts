// Проверка справки: разбор всех статей и правила из core/validate.ts.
// Запуск: node scripts/check-help.ts [--no-coverage]. Печатает по сообщению в строке, при любой ошибке — код 1.
// Тот же код вызывает vite-плагин на сборке (vite-plugins/helpCheck.ts).

import fs from 'node:fs'
import path from 'node:path'
import { HelpParseError, parseArticle } from '../src/help/core/frontmatter.ts'
import { validate } from '../src/help/core/validate.ts'
import type { Article } from '../src/help/core/types.ts'

function markdownFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return []
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? markdownFiles(path.join(dir, e.name)) : e.name.endsWith('.md') ? [path.join(dir, e.name)] : []))
    .sort()
}

/**
 * Допустимые значения поля `module`: id модулей со `status: 'available'` из src/platform/modules.ts и `platform`.
 * Файл читается как текст: он тянет иконки lucide и алиас `@/`, которые node без сборки не подключит.
 */
function knownModules(root: string): string[] {
  const src = fs.readFileSync(path.join(root, 'src/platform/modules.ts'), 'utf8')
  const ids = [...src.matchAll(/id: '([^']+)'[^}]*?status: '([^']+)'/g)].filter((m) => m[2] === 'available').map((m) => m[1])
  if (ids.length === 0) throw new Error('src/platform/modules.ts: не найдено ни одного доступного модуля — изменился формат MODULES?')
  return [...ids, 'platform']
}

/**
 * @param root корень фронта (папка с package.json)
 * @param coverage проверять ли, что каждый адрес из routes.json покрыт статьёй
 * @returns сообщения об ошибках; пустой список — всё в порядке
 */
export function checkHelp(root: string, coverage: boolean): string[] {
  const helpDir = path.join(root, 'src/help')
  const articles: Article[] = []
  const msgs: string[] = []
  for (const abs of markdownFiles(path.join(helpDir, 'articles'))) {
    const file = path.relative(root, abs).split(path.sep).join('/')
    try {
      articles.push(parseArticle(file, fs.readFileSync(abs, 'utf8')))
    } catch (e) {
      if (!(e instanceof HelpParseError)) throw e
      msgs.push(e.message)
    }
  }
  const routes: string[] = coverage ? JSON.parse(fs.readFileSync(path.join(helpDir, 'routes.json'), 'utf8')) : []
  return [...msgs, ...validate(articles, routes, knownModules(root))]
}

if (process.argv[1] && path.resolve(process.argv[1]) === import.meta.filename) {
  const msgs = checkHelp(path.resolve(import.meta.dirname, '..'), !process.argv.includes('--no-coverage'))
  for (const m of msgs) console.error(m)
  if (msgs.length > 0) process.exit(1)
  console.log('check:help — справка в порядке')
}
