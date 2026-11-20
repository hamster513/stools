/**
 * Права доступа: уровень пользователя в каждой области — модуле или
 * платформе. Матрицу считает сервер (объединение ролей групп, побеждает
 * старший уровень) и отдаёт в /api/auth/me; здесь только словарь и сравнение.
 */

/** Уровень в области; у платформы «write» не бывает. */
export type Level = 'deny' | 'read' | 'write' | 'admin'

/** Область прав: модуль или платформа (общие настройки). */
export type Area = 'attack' | 'siem' | 'vm' | 'ad' | 'ksc' | 'assets' | 'toolbox' | 'radar' | 'irp' | 'platform'

/** Области в порядке рейки, платформа последней. */
export const AREAS: readonly Area[] = ['attack', 'siem', 'vm', 'ad', 'ksc', 'assets', 'toolbox', 'radar', 'irp', 'platform']

/** Уровни в модуле — словами человека. */
export const LEVEL_TITLES: Record<Level, string> = {
  deny: 'запрет',
  read: 'аудитор',
  write: 'аналитик',
  admin: 'администратор',
}

/** Уровни платформы: «аналитика» в общих настройках нет. */
export const PLATFORM_LEVEL_TITLES: Record<Exclude<Level, 'write'>, string> = {
  deny: 'запрет',
  read: 'чтение',
  admin: 'администратор',
}

export type Access = Record<Area, Level>

const RANK: Record<Level, number> = { deny: 0, read: 1, write: 2, admin: 3 }

export function rank(l: Level): number {
  return RANK[l]
}

/** Не ниже ли уровень в области, чем требуется. Области нет в матрице — запрет. */
export function atLeast(a: Access, area: Area, l: Level): boolean {
  return rank(a[area] ?? 'deny') >= rank(l)
}
