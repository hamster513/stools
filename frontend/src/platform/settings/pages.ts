import type { ComponentType } from 'react'
import type { Area, Level } from '@/platform/access/types'
import { SettingsPage as SiemSettingsPage } from '@/modules/siem/pages/SettingsPage'
import { SettingsPage as VmSettingsPage } from '@/modules/vm/pages/SettingsPage'
import { SettingsPage as AdSettingsPage } from '@/modules/ad/pages/SettingsPage'
import { SettingsPage as KscSettingsPage } from '@/modules/ksc/pages/SettingsPage'
import { SettingsPage as AssetsSettingsPage } from '@/modules/assets/pages/SettingsPage'
import { SettingsPage as ToolboxSettingsPage } from '@/modules/toolbox/pages/SettingsPage'
import { SchedulesPage } from './pages/SchedulesPage'
import { ProfilePage } from './pages/ProfilePage'
import { AccessPage } from './pages/AccessPage'
import { AuditPage } from './pages/AuditPage'
import { LlmPage } from './pages/LlmPage'
import { AttackSettingsPage } from './pages/AttackSettingsPage'
import { FindingsSettingsPage } from './pages/FindingsSettingsPage'

/**
 * Раздел → какая область и какой уровень нужны, чтобы его открыть. null —
 * открыт всем: профиль и статусы находок (сохранить их может только
 * администратор платформы — это проверяет сама страница).
 */
export const PAGES = new Map<string, { page: ComponentType; nested?: boolean; need: [Area, Level] | null }>([
  ['schedules', { page: SchedulesPage, need: null }],
  ['profile', { page: ProfilePage, need: null }],
  ['findings', { page: FindingsSettingsPage, need: null }],
  // «Доступ» сам разбирает хвост пути: вкладки и карточки групп и ролей.
  ['access', { page: AccessPage, nested: true, need: ['platform', 'read'] }],
  ['audit', { page: AuditPage, need: ['platform', 'read'] }],
  ['llm', { page: LlmPage, need: ['platform', 'admin'] }],
  ['attack', { page: AttackSettingsPage, need: ['attack', 'write'] }],
  // Страница модуля открыта аналитику: загрузки и сбор — его работа. Настройку модуля
  // (подключения, расписания, справочники) сама страница оставляет администратору.
  ['siem', { page: SiemSettingsPage, need: ['siem', 'write'] }],
  ['vm', { page: VmSettingsPage, need: ['vm', 'write'] }],
  ['ad', { page: AdSettingsPage, need: ['ad', 'write'] }],
  ['ksc', { page: KscSettingsPage, need: ['ksc', 'write'] }],
  ['assets', { page: AssetsSettingsPage, need: ['assets', 'write'] }],
  ['toolbox', { page: ToolboxSettingsPage, need: ['toolbox', 'write'] }],
])

/** Что нужно, чтобы открыть раздел; null — открыт всем (или раздела нет: его адрес уводит на сводку). */
export function settingsNeed(section: string): [Area, Level] | null {
  return PAGES.get(section)?.need ?? null
}
