/**
 * Фасеты статусов для панели фильтров списков модулей (спека §5–§6): статус и
 * исполнитель (`me`, `none`, логин) — мультивыбор, «просроченные», «риск
 * истекает». Панель и чипы — platform/filters; здесь только описание фасетов,
 * параметры запроса и чипы. Без выбранного статуса сервер отдаёт открытые.
 * Здесь же общие для всех списков `toggleValue` и `valueChips`: внутри фасета
 * значения объединяются по «ИЛИ», и каждое выбранное значение — свой чип.
 */
import type { FilterChip } from '@/platform/filters/FiltersBar'
import { OPEN_STATUSES, STATUSES, STATUS_TITLES, type FindingStatus } from './types'

export interface FindingFacetFilters {
  status?: FindingStatus[]
  assignee?: string[]
  overdue?: boolean
  risk_expiring?: boolean
}

export const STATUS_OPTIONS = STATUSES.map((value) => ({ value, label: STATUS_TITLES[value] }))

export const ASSIGNEE_SPECIAL: Record<string, string> = { me: 'мои', none: 'без исполнителя' }

/**
 * Переключить значение фасета в мультивыборе; пустой выбор — фильтр снят
 * (undefined), а не «ничего не подходит».
 *   toggleValue(undefined, 'a')  → ['a']
 *   toggleValue(['a'], 'b')      → ['a', 'b']
 *   toggleValue(['a', 'b'], 'a') → ['b']
 *   toggleValue(['a'], 'a')      → undefined
 */
export function toggleValue<T extends string | number>(list: T[] | undefined, v: T): T[] | undefined {
  const next = list?.includes(v) ? list.filter((x) => x !== v) : [...(list ?? []), v]
  return next.length ? next : undefined
}

/** Фасеты, которые в старых ссылках приходили одной строкой через запятую (`?status=new,fixed`). */
const COMMA_COMPAT = ['status', 'disc_status']

/**
 * Значения фасета из ссылки: ключ повторяется (`?severity=high&severity=critical`).
 * Только у `status`/`disc_status` одно значение с запятой читается и по-старому —
 * так выглядят прежние ссылки; у остальных запятая — часть значения («DMZ, Moscow»).
 * С `allowed` незнакомые значения отбрасываются; пустой выбор и `all` — фильтр не задан.
 *   ?zone=DMZ%2C%20Moscow&zone=core → ['DMZ, Moscow', 'core']
 *   ?status=new,fixed               → ['new', 'fixed']
 */
export function listFrom<T extends string = string>(params: URLSearchParams, key: string, allowed?: readonly T[]): T[] | undefined {
  let raw = params.getAll(key)
  if (COMMA_COMPAT.includes(key) && raw.length === 1 && raw[0].includes(',')) raw = raw[0].split(',')
  if (raw.length === 1 && raw[0] === 'all') return undefined
  const picked = raw.filter((v): v is T => v !== '' && (!allowed || (allowed as readonly string[]).includes(v)))
  return picked.length ? picked : undefined
}

/**
 * «Не задано» — пустое значение фасета («без зоны», критичность «не задана») —
 * в адресе передаётся маркером `-`: пустой элемент списка `a,,b` сервер
 * отбрасывает, и фильтр молча терялся бы. В состоянии страницы и в теле
 * массовой смены (JSON-список) значение остаётся пустой строкой.
 *   toWire(['core', ''])   → ['core', '-']
 *   fromWire(['core', '-']) → ['core', '']
 */
export const UNSET_WIRE = '-'
export function toWire(list: string[] | undefined): string[] | undefined {
  return list?.map((v) => (v === '' ? UNSET_WIRE : v))
}
export function fromWire(list: string[] | undefined): string[] | undefined {
  return list?.map((v) => (v === UNSET_WIRE ? '' : v))
}

/** Переключить статус; пустой выбор — снова умолчание (открытые). */
export function toggleStatus(current: FindingStatus[] | undefined, status: FindingStatus): FindingStatus[] | undefined {
  return toggleValue(current, status)
}

/** Чипы многозначного фасета: по одному на значение («Критичность: high»), крестик снимает только его. */
export function valueChips<T extends string | number>(facet: string, list: T[] | undefined, label: (v: T) => string, set: (next: T[] | undefined) => void): FilterChip[] {
  return (list ?? []).map((v) => ({ label: `${facet}: ${label(v)}`, clear: () => set(toggleValue(list, v)) }))
}

/**
 * Статус при включении флага сроков. Счётчики флагов сервер считает без фильтра
 * статуса («риск истекает» — среди принятых, «просроченные» — среди открытых), и
 * список после щелчка должен показать их же: «риск истекает» снимает статус (сервер
 * возьмёт принятый риск), «просроченные» — если среди выбранных нет открытых.
 */
export function statusForFlag(flag: 'overdue' | 'risk_expiring', status: FindingStatus[] | undefined): FindingStatus[] | undefined {
  if (flag === 'risk_expiring') return undefined
  return status?.some((s) => OPEN_STATUSES.includes(s)) ? status : undefined
}

export function findingFacetParams(f: FindingFacetFilters): { status?: string[]; assignee?: string[]; overdue?: boolean; risk_expiring?: boolean } {
  return {
    status: f.status,
    assignee: f.assignee,
    overdue: f.overdue || undefined,
    risk_expiring: f.risk_expiring || undefined,
  }
}

/** Чипы выбранных фасетов; `names` — логин → имя из справочника исполнителей. */
export function findingFacetChips(f: FindingFacetFilters, set: (next: FindingFacetFilters) => void, names?: Map<string, string>): FilterChip[] {
  const chips: FilterChip[] = [
    ...valueChips('Статус', f.status, (s) => STATUS_TITLES[s], (status) => set({ ...f, status })),
    ...valueChips('Исполнитель', f.assignee, (a) => ASSIGNEE_SPECIAL[a] ?? names?.get(a) ?? a, (assignee) => set({ ...f, assignee })),
  ]
  if (f.overdue) chips.push({ label: 'Просроченные', clear: () => set({ ...f, overdue: undefined }) })
  if (f.risk_expiring) chips.push({ label: 'Риск истекает', clear: () => set({ ...f, risk_expiring: undefined }) })
  return chips
}
