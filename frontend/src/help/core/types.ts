// Типы справки. Без React и зависимостей: модуль подключается и из бандла Vite,
// и из vite-плагина / node-скрипта проверки.

export type Group = 'start' | 'module' | 'settings' | 'glossary'

export interface ArticleMeta {
  slug: string
  title: string
  group: Group
  /** id модуля или `platform`; у словаря необязателен */
  module?: string
  /** шаблоны адресов, для которых статья — «статья страницы» */
  routes: string[]
  where?: string
  /** «Кому» и блок «Что здесь можно» */
  levels?: { read?: string; write?: string; admin?: string }
  /** slug'и статей словаря */
  concepts: string[]
  order?: number
}

export interface Article extends ArticleMeta {
  /** markdown после фронтматтера */
  body: string
  /** путь файла — для сообщений об ошибках */
  file: string
  /** sections['Что это'] = markdown блока под `## Что это` */
  sections: Record<string, string>
}
