import { useEffect, useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { useImportApply, useImportPreview } from '../api/queries'
import type { ImportAction } from '../api/types'

const ACTION_TITLES: Record<ImportAction, string> = {
  new: 'новый — будет создан',
  revive: 'удалённый — будет возвращён',
  changed: 'отличается от библиотеки',
  same: 'без изменений',
}

const message = (e: unknown, fallback: string) => (e instanceof ApiRequestError ? e.message : fallback)

/**
 * Загрузка библиотеки из YAML в два шага: файл → предпросмотр (что будет создано, возвращено, заменено) → «Применить».
 * Главный — интерфейс: изменённый хант заменяется только по галочке «заменить» (по умолчанию снята),
 * новые и возвращаемые применяются всегда, совпадающие не трогаются. Файл читается заново при применении,
 * поэтому остаётся в состоянии диалога.
 */
export function ImportDialog({ onClose }: { onClose: () => void }) {
  const preview = useImportPreview()
  const apply = useImportApply()
  const [file, setFile] = useState<File | null>(null)
  const [replace, setReplace] = useState<Set<string>>(new Set())

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !apply.isPending) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [apply.isPending, onClose])

  function pick(next: File | null) {
    setFile(next)
    setReplace(new Set())
    apply.reset()
    preview.reset()
    if (next) preview.mutate(next)
  }

  function toggle(code: string, on: boolean) {
    setReplace((prev) => {
      const next = new Set(prev)
      if (on) next.add(code)
      else next.delete(code)
      return next
    })
  }

  // Предпросмотр принимается, только если он построен по выбранному сейчас файлу: ответ по прежнему файлу при быстрой смене выбора игнорируется.
  const shown = preview.data && preview.variables === file ? preview.data : undefined
  const rows = shown?.rows ?? []
  const always = rows.filter((r) => r.action === 'new' || r.action === 'revive').length
  const replaced = rows.filter((r) => r.action === 'changed' && replace.has(r.code)).map((r) => r.code)
  const nothing = always + replaced.length === 0
  const result = apply.data

  return (
    <div role="dialog" aria-modal="true" aria-label="Загрузить библиотеку из YAML" className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
      <div className="flex max-h-full w-full max-w-3xl flex-col rounded border border-grid bg-surface p-4">
        <div className="mb-3 text-sm font-semibold text-text">Загрузить библиотеку из YAML</div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {!result && (
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text">Файл библиотеки</span>
              <input
                type="file"
                accept=".yaml,.yml,text/yaml"
                onChange={(e) => pick(e.target.files?.[0] ?? null)}
                disabled={apply.isPending}
                className="block w-full text-xs text-text file:mr-3 file:rounded file:border file:border-border file:bg-transparent file:px-3 file:py-1.5 file:text-xs file:text-text"
              />
            </label>
          )}

          {preview.isPending && <p className="mt-3 text-xs text-text-secondary">Разбираю файл…</p>}
          {preview.isError && <p className="mt-3 text-xs text-kind-1" role="alert">{message(preview.error, 'Не удалось разобрать файл')}</p>}

          {shown && !result && (
            <div className="mt-3">
              {rows.length === 0 ? (
                <p className="text-xs text-text-secondary">В файле нет хантов.</p>
              ) : (
                <table className="w-full table-fixed border-collapse text-xs">
                  <colgroup>
                    <col style={{ width: 120 }} />
                    <col style={{ width: 220 }} />
                    <col />
                    <col style={{ width: 96 }} />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                      <th scope="col" className="px-2 py-1.5 font-semibold">Хант</th>
                      <th scope="col" className="px-2 py-1.5 font-semibold">Что будет</th>
                      <th scope="col" className="px-2 py-1.5 font-semibold">Что отличается</th>
                      <th scope="col" className="px-2 py-1.5 font-semibold">Заменить</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.code} className="border-b border-grid align-top">
                        <td className="truncate px-2 py-1.5 font-mono text-text" title={r.code}>{r.code}</td>
                        <td className="px-2 py-1.5 text-text">{ACTION_TITLES[r.action]}</td>
                        <td className="px-2 py-1.5 break-words text-text-secondary">{r.changes.length ? r.changes.join(', ') : '—'}</td>
                        <td className="px-2 py-1.5">
                          {r.action === 'changed' ? (
                            <input
                              type="checkbox"
                              checked={replace.has(r.code)}
                              onChange={(e) => toggle(r.code, e.target.checked)}
                              disabled={apply.isPending}
                              aria-label={`Заменить ${r.code}`}
                              className="accent-primary"
                            />
                          ) : (
                            <span className="text-text-secondary">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="mt-2 text-[11px] text-text-secondary">
                В файле хантов: {shown.hunts}. Изменённый хант заменяется только по галочке — иначе остаётся как в интерфейсе.
              </p>
            </div>
          )}

          {apply.isError && <p className="mt-3 text-xs text-kind-1" role="alert">{message(apply.error, 'Не удалось применить файл')}</p>}

          {result && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs" role="status">
              <dt className="text-text-secondary">Создано</dt>
              <dd className="font-mono tabular-nums text-text">{result.created}</dd>
              <dt className="text-text-secondary">Заменено</dt>
              <dd className="font-mono tabular-nums text-text">{result.replaced}</dd>
              <dt className="text-text-secondary">Пропущено</dt>
              <dd className="font-mono tabular-nums text-text">{result.skipped}</dd>
            </dl>
          )}
        </div>

        <div className="mt-4 flex justify-end gap-2">
          {result ? (
            <Button variant="primary" onClick={onClose}>Закрыть</Button>
          ) : (
            <>
              <Button onClick={onClose} disabled={apply.isPending}>Отмена</Button>
              <Button
                variant="primary"
                loading={apply.isPending}
                disabled={!file || !shown || nothing}
                title={shown && nothing ? 'Нечего применять: отметьте «заменить» у изменённых хантов' : undefined}
                onClick={() => file && apply.mutate({ file, replace: replaced })}
              >
                Применить
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
