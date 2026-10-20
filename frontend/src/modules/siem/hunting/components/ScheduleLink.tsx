import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

/**
 * Состояние ханта в расписании ночных прогонов — ссылка в планировщик, где оно и меняется.
 * Щелчок не должен долетать до строки списка, у которой есть свой переход (открыть карточку), поэтому он гасится здесь.
 */
export function ScheduleLink({ enabled, className }: { enabled: boolean; className?: string }) {
  return (
    <span onClick={(e) => e.stopPropagation()}>
      <Link
        to="/siem/hunting/scheduler"
        title="Включение ханта — в Планировщике"
        className={cn('rounded text-xs hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', enabled ? 'text-primary' : 'text-text-secondary', className)}
      >
        {enabled ? 'в расписании' : 'не запускается'}
      </Link>
    </span>
  )
}
