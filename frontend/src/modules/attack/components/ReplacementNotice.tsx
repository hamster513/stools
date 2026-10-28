import { AlertTriangle, X } from 'lucide-react'
import { useAttackBundle, useDismissReplacementNotice } from '@/modules/attack/api/queries'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

/**
 * Сообщение о том, что поставка перекрыла загруженную матрицу.
 *
 * Показывается, пока человек не подтвердит, что увидел, и намеренно не
 * привязано к экрану настроек: заказчик загружал матрицу руками, а
 * последствия замены он увидит там, где работает — в покрытии и разметке.
 * Молчаливая подмена оставила бы его гадать, откуда взялась другая версия.
 */
export function ReplacementNotice({ className }: { className?: string }) {
  // Сообщение читают все — замена версии объясняет пометки на разметке;
  // «я увидел» пишется в настройки базы ATT&CK — это администратору модуля ATT&CK.
  const { admin } = useCan('attack')
  const bundle = useAttackBundle()
  const dismiss = useDismissReplacementNotice()
  const notice = bundle.data?.replacement

  if (!notice) return null

  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-2 rounded border px-3 py-2 text-xs text-text',
        notice.downgraded ? 'border-kind-1/40 bg-kind-1/5' : 'border-kind-3/40 bg-kind-3/5',
        className,
      )}
      role="status"
    >
      <AlertTriangle
        size={14}
        className={notice.downgraded ? 'text-kind-1' : 'text-kind-3'}
        aria-hidden
      />
      <span>
        Матрицу ATT&CK заменила поставка: была версия{' '}
        <span className="font-mono">{notice.replaced_version}</span>, стала{' '}
        <span className="font-mono">{notice.current_version}</span>.
        {notice.downgraded ? (
          <>
            {' '}
            Это откат назад — обновление софта принесло матрицу старее той, что вы загружали.
            Разметка сохранена, но сделанная на прежней версии помечена на пересмотр. Чтобы
            вернуться, загрузите нужную матрицу заново.
          </>
        ) : (
          <> Разметка сохранена; сделанная на прежней версии помечена на пересмотр.</>
        )}
      </span>
      {admin && (
        <button
          type="button"
          onClick={() => dismiss.mutate()}
          className="ml-auto rounded px-1.5 py-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          aria-label="Я увидел"
          title="Я увидел"
        >
          <X size={12} aria-hidden />
        </button>
      )}
    </div>
  )
}
