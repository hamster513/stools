// Типы справки. Без React и зависимостей: модуль подключается и из бандла Vite,
// и из vite-плагина / node-скрипта проверки.

export type Group = 'start' | 'news' | 'module' | 'settings' | 'glossary'

export interface ArticleMeta {
  slug: string
  title: string
  group: Group
  /** id модуля или `platform`; у словаря необязателен */
  module?: string
  /** шаблоны адресов, для которых статья — «статья страницы» */
  routes: string[]
  where?: string
  /** «Кому» и блок «Что здесь можно»; `any` — страница открыта всем вошедшим, одна строка вместо уровней */
  levels?: { read?: string; write?: string; admin?: string; any?: string }
  /** slug'и статей словаря */
  concepts: string[]
  order?: number
  /** узел оглавления внутри группы «Настройки» (например, «Доступ»): статьи с одним section идут под ним */
  section?: string
}

export interface TocItem {
  slug: string
  title: string
  children?: TocItem[]
}

export interface Article extends ArticleMeta {
  /** markdown после фронтматтера */
  body: string
  /** путь файла — для сообщений об ошибках */
  file: string
  /** sections['Что это'] = markdown блока под `## Что это` */
  sections: Record<string, string>
}
