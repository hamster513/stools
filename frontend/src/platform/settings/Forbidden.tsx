import { Lock } from 'lucide-react'
import { useMe } from '@/api/auth'
import { EmptyState } from '@/components/ui/EmptyState'
import { firstReadableModule } from '@/lib/can'
import { Link } from '@/lib/router'
import { findModule } from '@/platform/modules'

const TEXT = {
  module: {
    title: 'Модуль недоступен вашим группам',
    description: 'Доступ к модулю дают группы, в которых вы состоите. Чтобы его получить, обратитесь к администратору STools.',
  },
  settings: {
    title: 'Раздел настроек недоступен',
    description: 'Этот раздел открыт уровню выше вашего. Доступные разделы — в меню слева.',
  },
} as const

/**
 * Отказ по правам — не ошибка: экран объясняет, почему сюда нельзя, и
 * уводит туда, где работать можно, — в первый открытый модуль, а если
 * таких нет, в свой профиль.
 */
export function Forbidden({ kind }: { kind: 'module' | 'settings' }) {
  const { data: me } = useMe()
  const home = firstReadableModule(me?.access)
  const text = TEXT[kind]
  return (
    <div className="p-6">
      <EmptyState
        icon={Lock}
        title={text.title}
        description={text.description}
        action={
          <Link to={home ? `/${home}` : '/settings/profile'} className="text-sm text-primary underline underline-offset-2">
            {home ? `${findModule(home)?.title ?? home} →` : 'Мой профиль →'}
          </Link>
        }
      />
    </div>
  )
}
