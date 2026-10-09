/** Типы модуля ToolBox — по схемам backend/api/modules/toolbox/routers/scrub.py. */
import type { Job } from '@/platform/collector/types'

/**
 * Задание очистки в списке и при опросе хода: общий роутер задач платформы отдаёт только поля `Job`.
 * Имя файла, размер и счётчики приходят отдельно — `/info` (JobInfo), только на карточке.
 */
export type ScrubJob = Job

export interface ScrubStats {
  files?: number
  skipped?: number
  /** Сколько уникальных значений найдено по категориям. */
  findings?: Partial<Record<string, number>>
  /** Сколько вхождений заменено по категориям — после применения. */
  replaced?: Partial<Record<string, number>>
}

export interface JobInfo {
  id: number
  input_name: string
  input_size: number
  input_kind: 'file' | 'text'
  files_deleted: boolean
  result_name: string
  stats: ScrubStats
  users_from_ad: boolean
}

export interface Finding {
  id: number
  kind: string
  value: string
  alias: string
  count: number
  /** До трёх кусков текста вокруг значения; аудитору — пусто. */
  contexts: string[]
  first_file: string
  checked: boolean
  /** Найдено авто-поиском, а не по словарю. */
  auto: boolean
  /** Псевдоним уже в таблице соответствий — сменить его здесь нельзя. */
  stored: boolean
}

export interface FindingGroup {
  kind: string
  total: number
  checked: number
}

export interface FindingsResponse {
  groups: FindingGroup[]
  items: Finding[]
  total: number
}

export interface FindingsQuery {
  kind?: string
  q?: string
  offset?: number
  /** По умолчанию — страница в 200; `1` — только счётчики групп. */
  limit?: number
}

export interface FindingsPatch {
  checks: Record<number, boolean>
  aliases: Record<number, string>
  words: string[]
}

export type Download = 'result' | 'report' | 'mapping'

/** Порядок — как приоритет детекторов на бэкенде (types.KINDS). */
export const KIND_ORDER: readonly string[] = ['secret', 'word', 'user', 'host', 'domain', 'sid', 'ip4', 'ip6', 'mac']

export const KIND_LABELS: Record<string, string> = {
  ip4: 'IPv4',
  ip6: 'IPv6',
  mac: 'MAC',
  domain: 'Домены',
  host: 'Хосты',
  user: 'Учётные записи',
  sid: 'SID',
  secret: 'Секреты',
  word: 'Слова',
}

export const JOB_KIND_LABELS: Record<string, string> = { scan: 'сканирование', apply: 'очистка' }

export const STAGE_LABELS: Record<string, string> = {
  pending: 'ожидание',
  scan: 'поиск значений',
  apply: 'замена значений',
  done: 'готово',
}

export const STATUS_LABELS: Record<Job['status'], string> = {
  running: 'идёт',
  done: 'готово',
  failed: 'ошибка',
  cancelled: 'отменено',
}

export const STATUS_CLASS: Record<Job['status'], string> = {
  running: 'text-focus-ring',
  done: 'text-kind-accepted',
  failed: 'text-kind-1',
  cancelled: 'text-text-secondary',
}

/** Что сервер принимает как текст без оговорок (спека §3); остальное читается как текст, если в нём нет нулевых байтов. */
export const KNOWN_EXTENSIONS = ['.json', '.gz', '.zip', '.csv', '.txt', '.log', '.xml', '.conf', '.ini', '.yaml', '.yml']

export const MB = 1024 * 1024

/** Размер для подписи: от мегабайта — с десятой, меньше — килобайты вверх. */
export function formatSize(bytes: number): string {
  return bytes >= MB ? `${(bytes / MB).toFixed(1)} МБ` : `${Math.ceil(bytes / 1024)} КБ`
}
export const FILE_MAX = 200 * MB
export const TEXT_MAX = 1 * MB
