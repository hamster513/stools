import { useEffect, useRef } from 'react'
import { Button } from '@/components/ui/Button'

export function DeleteFindingsDialog({ count, allByFilter, pending, error, onCancel, onConfirm }: {
  count: number
  allByFilter: boolean
  pending: boolean
  error?: string
  onCancel: () => void
  onConfirm: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    dialog?.showModal()
    return () => dialog?.close()
  }, [])
  return <dialog ref={ref} aria-labelledby="delete-findings-title" aria-describedby="delete-findings-description"
    className="m-auto w-full max-w-md rounded border border-grid bg-surface p-5 text-text backdrop:bg-black/60"
    onCancel={e => { e.preventDefault(); if (!pending) onCancel() }}>
    <h2 id="delete-findings-title" className="mb-3 text-sm font-semibold">Удалить находки: {count}?</h2>
    <p id="delete-findings-description" className="mb-4 text-xs text-text-secondary">
      {allByFilter ? 'Будут удалены все находки по текущему фильтру, включая другие страницы.' : 'Будут удалены отмеченные находки.'}
      {' '}Их события, комментарии и история обработки тоже будут удалены без возможности восстановления в интерфейсе.
      Ханты и запросы сохранятся. Повторный запуск может создать новые находки.
    </p>
    {error && <p role="alert" className="mb-3 text-xs text-kind-1">{error}</p>}
    <div className="flex justify-end gap-2">
      <Button autoFocus disabled={pending} onClick={onCancel}>Отмена</Button>
      <Button variant="danger" loading={pending} onClick={onConfirm}>Удалить {count}</Button>
    </div>
  </dialog>
}
