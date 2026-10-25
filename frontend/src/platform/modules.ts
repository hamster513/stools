import { Bug, Grid3x3, Network, Radar, Server, ShieldAlert, Users, Wrench, type LucideIcon } from 'lucide-react'

export type ModuleStatus = 'available' | 'planned'

export interface ModuleSpec {
  /** Первый сегмент пути: /siem/…, /av, … и префикс API /api/<id>. */
  id: string
  /** Короткий код для рейки — полное имя туда не помещается. */
  code: string
  title: string
  description: string
  icon: LucideIcon
  status: ModuleStatus
}

/**
 * Реестр модулей STools. Статичен намеренно: набор модулей меняется
 * выпуском продукта, а не настройкой, и ручка на бэкенде для него ни к чему.
 * Порядок здесь — порядок в рейке: работающие модули выше заглушек.
 */
export const MODULES: readonly ModuleSpec[] = [
  {
    id: 'attack',
    code: 'ATT&CK',
    title: 'Матрица ATT&CK',
    description:
      'Одна матрица на все модули: покрытие правилами SIEM, экспозиция по уязвимостям VM и находкам AD, разрывы между ними.',
    icon: Grid3x3,
    status: 'available',
  },
  {
    id: 'siem',
    code: 'SIEM',
    title: 'SIEM Rules Analyzer',
    description:
      'База знаний MaxPatrol SIEM: средовые значения в правилах, клоны, табличные списки, покрытие ATT&CK.',
    icon: Radar,
    status: 'available',
  },
  {
    id: 'vm',
    code: 'VM',
    title: 'Vulnerability Management',
    description:
      'Хосты и CVE из MaxPatrol VM, обогащение EPSS, NVD, ExploitDB и Metasploit, риск по формуле: что чинить первым.',
    icon: ShieldAlert,
    status: 'available',
  },
  {
    id: 'ad',
    code: 'AD',
    title: 'Active Directory',
    description:
      'Двадцать проверок домена: DCSync, привилегированные группы, делегация, Kerberoast, ACL, шаблоны AD CS.',
    icon: Users,
    status: 'available',
  },
  {
    id: 'ksc',
    code: 'AV',
    title: 'Антивирус',
    description:
      'Kaspersky Security Center: покрытие относительно AD, устройства без агента и защиты, состояние компонентов, базы, политики и задачи.',
    icon: Bug,
    status: 'available',
  },
  {
    id: 'assets',
    code: 'AST',
    title: 'Assets',
    description:
      'Реестр активов из VM, антивируса, AD, сканера сети и DNS: где актив засветился, какие данные устарели, кого никто не описал.',
    icon: Server,
    status: 'available',
  },
  {
    id: 'toolbox',
    code: 'TBX',
    title: 'ToolBox',
    description:
      'Утилиты для ИБ-специалиста: очистка файлов и текста от адресов, имён, учёток и секретов перед передачей наружу.',
    icon: Wrench,
    status: 'available',
  },
  {
    id: 'fw',
    code: 'FW',
    title: 'Сетевой периметр',
    description:
      'Правила межсетевых экранов и открытые сервисы: лишние разрешения, мёртвые правила, доступ снаружи.',
    icon: Network,
    status: 'planned',
  },
]

export function findModule(id: string): ModuleSpec | null {
  return MODULES.find((m) => m.id === id) ?? null
}

/** Название модуля для заголовка его страницы настроек. */
export function moduleTitle(id: string): string {
  return findModule(id)?.title ?? id
}
