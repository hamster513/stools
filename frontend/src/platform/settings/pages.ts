import type { ComponentType } from 'react'
import type { Area, Level } from '@/platform/access/types'
import { SettingsPage as SiemSettingsPage } from '@/modules/siem/pages/SettingsPage'
import { LogonImportPage } from '@/modules/siem/logons/ImportPage'
import { HuntingSettingsPage } from '@/modules/siem/hunting/pages/settings/HuntingSettingsPage'
import { SettingsPage as VmSettingsPage } from '@/modules/vm/pages/SettingsPage'
import { SettingsPage as AdSettingsPage } from '@/modules/ad/pages/SettingsPage'
import { SettingsPage as KscSettingsPage } from '@/modules/ksc/pages/SettingsPage'
import { SettingsPage as AssetsSettingsPage } from '@/modules/assets/pages/SettingsPage'
import { SettingsPage as ToolboxSettingsPage } from '@/modules/toolbox/pages/SettingsPage'
import { RadarSettingsPage } from '@/modules/radar/SettingsPage'
import { DiagnosticsPage } from './pages/DiagnosticsPage'
import { StoragePage } from './pages/StoragePage'
import { SchedulesPage } from './pages/SchedulesPage'
import { ProfilePage } from './pages/ProfilePage'
import { AccessPage } from './pages/AccessPage'
import { AuditPage } from './pages/AuditPage'
import { MailPage } from './pages/MailPage'
import { LlmPage } from './pages/LlmPage'
import { AttackSettingsPage } from './pages/AttackSettingsPage'
import { FindingsSettingsPage } from './pages/FindingsSettingsPage'

/**
 * Раздел → какая область и какой уровень нужны, чтобы его открыть. null —
 * открыт всем: профиль и статусы находок (сохранить их может только
 * администратор платформы — это проверяет сама страница).
 */
export const PAGES = new Map<string, { page: ComponentType; nested?: boolean; need: [Area, Level] | null }>([
  ['diagnostics', { page: DiagnosticsPage, nested: true, need: ['platform', 'admin'] }],
  ['storage', { page: StoragePage, need: ['platform', 'read'] }],
  ['schedules', { page: SchedulesPage, need: null }],
  ['profile', { page: ProfilePage, need: null }],
  ['findings', { page: FindingsSettingsPage, need: null }],
  // «Доступ» сам разбирает хвост пути: вкладки и карточки групп и ролей.
  ['access', { page: AccessPage, nested: true, need: ['platform', 'read'] }],
  ['audit', { page: AuditPage, need: ['platform', 'read'] }],
  ['mail', { page: MailPage, need: ['platform', 'admin'] }],
  ['llm', { page: LlmPage, need: ['platform', 'admin'] }],
  ['attack', { page: AttackSettingsPage, need: ['attack', 'write'] }],
  // Страница модуля открыта аналитику: загрузки и сбор — его работа. Настройку модуля
  // (подключения, расписания, справочники) сама страница оставляет администратору.
  ['siem', { page: SiemSettingsPage, need: ['siem', 'write'] }],
  ['siem-logons', { page: LogonImportPage, need: ['siem', 'write'] }],
  ['siem-hunting', { page: HuntingSettingsPage, need: ['siem', 'write'] }],
  ['vm', { page: VmSettingsPage, need: ['vm', 'write'] }],
  ['ad', { page: AdSettingsPage, need: ['ad', 'write'] }],
  ['ksc', { page: KscSettingsPage, need: ['ksc', 'write'] }],
  ['assets', { page: AssetsSettingsPage, need: ['assets', 'write'] }],
  ['radar', { page: RadarSettingsPage, need: ['radar', 'write'] }],
  ['toolbox', { page: ToolboxSettingsPage, need: ['toolbox', 'write'] }],
])

/** Что нужно, чтобы открыть раздел; null — открыт всем (или раздела нет: его адрес уводит на сводку). */
export function settingsNeed(section: string): [Area, Level] | null {
  return PAGES.get(section)?.need ?? null
}
