import { AlertTriangle } from 'lucide-react'
import { Button } from './Button'

interface ErrorStateProps {
  message: string
  onRetry?: () => void
}

/** Ошибка называет причину и путь исправления, не просто «что-то пошло не так». */
export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded border border-kind-1/40 bg-kind-1/5 px-6 py-16 text-center">
      <AlertTriangle size={28} strokeWidth={1.5} className="text-kind-1" aria-hidden />
      <p className="max-w-md text-sm text-text">{message}</p>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry}>
          Повторить
        </Button>
      )}
    </div>
  )
}
