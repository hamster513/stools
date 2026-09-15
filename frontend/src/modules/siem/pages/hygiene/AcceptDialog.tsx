import { useEffect, useRef, useState } from 'react'
import type { FindingListItem } from '@/modules/siem/api/types'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

interface AcceptDialogProps {
  finding: FindingListItem | null
  pending: boolean
  onConfirm: (reason: string) => void
  onCancel: () => void
}

/** Принять как норму без обоснования нельзя — кнопка неактивна, пока поле пустое. */
export function AcceptDialog({ finding, pending, onConfirm, onCancel }: AcceptDialogProps) {
  const [reason, setReason] = useState('')
  const open = finding !== null
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (open) {
      setReason('')
      const id = setTimeout(() => textareaRef.current?.focus(), 0)
      return () => clearTimeout(id)
    }
  }, [open, finding?.id])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
    }
    if (open) document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onCancel])

  if (!open) return null

  const trimmed = reason.trim()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div
        role="dialog"
        aria-label="Принять находку как норму"
        className={cn(
          'w-full max-w-md rounded border border-grid bg-surface p-4 shadow-lg',
          'transition-[transform,opacity] duration-200',
        )}
      >
        <h2 className="mb-1 text-sm font-semibold text-text">Принять как норму</h2>
        <p className="mb-3 truncate font-mono text-xs text-text-secondary" title={finding.object_name}>
          {finding.object_name} · {finding.field}
        </p>
        <label className="flex flex-col gap-1.5">
          <span className="text-xs text-text-secondary">Обоснование (обязательно)</span>
          <textarea
            ref={textareaRef}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder="Например: адрес — константа шлюза мониторинга, вынести в список нецелесообразно"
            className="resize-none rounded border border-border bg-app-bg px-2.5 py-2 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
        </label>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Отмена
          </Button>
          <Button variant="primary" disabled={!trimmed} loading={pending} onClick={() => onConfirm(trimmed)}>
            Принять
          </Button>
        </div>
      </div>
    </div>
  )
}
