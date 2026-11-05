import type { ScheduleView } from '@/platform/collector/types'

export const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс']

export function scheduleText(s: ScheduleView | null): string {
  if (!s) return 'Вручную'
  const timing = s.weekdays?.length
    ? s.weekdays.map((d) => DAYS[d]).join(', ') + ' в ' + s.run_time
    : `Каждые ${s.interval_hours} ч` + (s.window_from ? ` с ${s.window_from} до ${s.window_to}` : '')
  return s.enabled ? timing : `Выключено · ${timing}`
}
