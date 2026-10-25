import { Lock } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { Link } from '@/lib/router'

/**
 * Отказ по правам — не ошибка: экран объясняет, почему сюда нельзя, и
 * уводит туда, где работать можно.
 */
export function Forbidden() {
  return (
    <div className="p-6">
      <EmptyState
        icon={Lock}
        title="Недостаточно прав"
        description="Этот раздел настроек доступен администратору. Настройки модулей и сводка данных открыты всем — они в меню слева."
        action={
          <Link to="/attack" className="text-sm text-primary underline underline-offset-2">
            К матрице ATT&CK →
          </Link>
        }
      />
    </div>
  )
}
