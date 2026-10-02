/**
 * Фасеты статусов для панели фильтров списков модулей (спека §5–§6): статус
 * (мультивыбор), исполнитель (`me`, `none`, логин), «просроченные», «риск
 * истекает». Панель и чипы — platform/filters; здесь только описание фасетов,
 * параметры запроса и чипы. Без выбранного статуса сервер отдаёт открытые.
 */
import type { FilterChip } from '@/platform/filters/FiltersBar'
import { STATUSES, STATUS_TITLES, type FindingStatus } from './types'

export interface FindingFacetFilters {
  status?: FindingStatus[]
  assignee?: string
  overdue?: boolean
  risk_expiring?: boolean
}

export const STATUS_OPTIONS = STATUSES.map((value) => ({ value, label: STATUS_TITLES[value] }))

export const ASSIGNEE_SPECIAL: Record<string, string> = { me: 'мои', none: 'без исполнителя' }

/** Переключить статус в мультивыборе; пустой выбор — снова умолчание (открытые). */
export function toggleStatus(current: FindingStatus[] | undefined, status: FindingStatus): FindingStatus[] | undefined {
  const next = current?.includes(status) ? current.filter((s) => s !== status) : [...(current ?? []), status]
  return next.length ? next : undefined
}

export function findingFacetParams(f: FindingFacetFilters): Record<string, string | boolean | undefined> {
  return {
    status: f.status?.join(','),
    assignee: f.assignee,
    overdue: f.overdue || undefined,
    risk_expiring: f.risk_expiring || undefined,
  }
}

/** Чипы выбранных фасетов; `names` — логин → имя из справочника исполнителей. */
export function findingFacetChips(f: FindingFacetFilters, set: (next: FindingFacetFilters) => void, names?: Map<string, string>): FilterChip[] {
  const chips: FilterChip[] = []
  if (f.status) chips.push({ label: `Статус: ${f.status.map((s) => STATUS_TITLES[s]).join(', ')}`, clear: () => set({ ...f, status: undefined }) })
  if (f.assignee) {
    const who = ASSIGNEE_SPECIAL[f.assignee] ?? names?.get(f.assignee) ?? f.assignee
    chips.push({ label: `Исполнитель: ${who}`, clear: () => set({ ...f, assignee: undefined }) })
  }
  if (f.overdue) chips.push({ label: 'Просроченные', clear: () => set({ ...f, overdue: undefined }) })
  if (f.risk_expiring) chips.push({ label: 'Риск истекает', clear: () => set({ ...f, risk_expiring: undefined }) })
  return chips
}
