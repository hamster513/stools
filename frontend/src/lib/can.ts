import { useMe } from '@/api/auth'
import { useRouter } from '@/lib/router'
import { AREAS, atLeast, type Access, type Area, type Level } from '@/platform/access/types'
import { findModule } from '@/platform/modules'

export interface Can {
  /** Область, о которой спрашивали; null — страница над модулями. */
  area: Area | null
  level: Level
  read: boolean
  write: boolean
  admin: boolean
  /** Общие настройки: читать разделы платформы и менять их. */
  platform: { read: boolean; admin: boolean }
  /** Хоть один модуль открыт на чтение / на запись. */
  anyRead: boolean
  anyWrite: boolean
}

const MODULE_AREAS = AREAS.filter((a) => a !== 'platform' && a !== 'irp')

/** Модуль текущего адреса: /<модуль>/… и страница его настроек /settings/<модуль>. */
function areaOfPath(path: string): Area | null {
  const [, first = '', second = ''] = path.split('/')
  const id = findModule(first === 'settings' ? second : first)?.id
  return MODULE_AREAS.find((a) => a === id) ?? null
}

/**
 * Что можно текущему пользователю в области. Сервер проверяет права сам;
 * здесь только решается, показывать ли элемент управления: аудитор не должен
 * видеть кнопки, которые для него не работают.
 *
 * Без аргумента область — модуль текущего адреса. Страницы над модулями
 * («Мои находки», сводка настроек) передают модуль явно; без него
 * read/write/admin ложны.
 */
export function useCan(area?: Area): Can {
  const { data } = useMe()
  const { path } = useRouter()
  const access: Access | undefined = data?.access
  const target = area ?? areaOfPath(path)
  const level: Level = access && target ? (access[target] ?? 'deny') : 'deny'
  const has = (a: Area, l: Level) => (access ? atLeast(access, a, l) : false)
  return {
    area: target,
    level,
    read: target ? has(target, 'read') : false,
    write: target ? has(target, 'write') : false,
    admin: target ? has(target, 'admin') : false,
    platform: { read: has('platform', 'read'), admin: has('platform', 'admin') },
    anyRead: MODULE_AREAS.some((a) => has(a, 'read')),
    anyWrite: MODULE_AREAS.some((a) => has(a, 'write')),
  }
}

/** Первый модуль, открытый пользователю на чтение; null — ни одного. */
export function firstReadableModule(access: Access | undefined): Area | null {
  if (!access) return null
  return MODULE_AREAS.find((a) => atLeast(access, a, 'read')) ?? null
}
