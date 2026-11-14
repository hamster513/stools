import { Binary, Calculator, EyeOff, SquareTerminal, ListFilter, FileJson, Workflow, Regex, FileKey, type LucideIcon } from 'lucide-react'

export interface ToolboxTab {
  to: string
  label: string
  match: (path: string) => boolean
}

export interface ToolboxSection {
  to: string
  label: string
  icon: LucideIcon
  /** Вкладки сверху над страницей; у раздела без вкладок — только заголовок. */
  tabs: ToolboxTab[]
  match: (path: string) => boolean
}

const exact = (to: string) => (p: string) => p === to

// Карточка и форма задания живут под /toolbox/scrub/… — это вкладка «Задания» раздела Blindspot.
const BLINDSPOT_TABS: ToolboxTab[] = [
  { to: '/toolbox', label: 'Задания', match: (p) => p === '/toolbox' || p.startsWith('/toolbox/scrub/') },
  { to: '/toolbox/reverse', label: 'Обратный перевод', match: exact('/toolbox/reverse') },
  { to: '/toolbox/aliases', label: 'Соответствия', match: exact('/toolbox/aliases') },
]

const LINUX_TABS: ToolboxTab[] = [
  { to: '/toolbox/linux', label: 'Unix time', match: exact('/toolbox/linux') },
  { to: '/toolbox/linux/cron', label: 'Cron', match: exact('/toolbox/linux/cron') },
]

/** Разделы модуля ToolBox: пункты меню слева, у каждого — шапка с заголовком и вкладками. */
export const TOOLBOX_SECTIONS: ToolboxSection[] = [
  { to: '/toolbox', label: 'Blindspot', icon: EyeOff, tabs: BLINDSPOT_TABS, match: (p) => BLINDSPOT_TABS.some((t) => t.match(p)) },
  { to: '/toolbox/compare', label: 'Сравнение', icon: ListFilter, tabs: [], match: exact('/toolbox/compare') },
  { to: '/toolbox/data', label: 'Данные и логи', icon: FileJson, tabs: [], match: exact('/toolbox/data') },
  { to: '/toolbox/decoder', label: 'Декодер', icon: Workflow, tabs: [], match: exact('/toolbox/decoder') },
  { to: '/toolbox/regex', label: 'Regex', icon: Regex, tabs: [], match: exact('/toolbox/regex') },
  { to: '/toolbox/certificates', label: 'Сертификаты', icon: FileKey, tabs: [], match: exact('/toolbox/certificates') },
  { to: '/toolbox/base64', label: 'Base64', icon: Binary, tabs: [], match: exact('/toolbox/base64') },
  { to: '/toolbox/ip', label: 'IP-калькулятор', icon: Calculator, tabs: [], match: exact('/toolbox/ip') },
  { to: '/toolbox/linux', label: 'Linux', icon: SquareTerminal, tabs: LINUX_TABS, match: (p) => LINUX_TABS.some((t) => t.match(p)) },
]

export const sectionFor = (path: string) => TOOLBOX_SECTIONS.find((s) => s.match(path)) ?? null
