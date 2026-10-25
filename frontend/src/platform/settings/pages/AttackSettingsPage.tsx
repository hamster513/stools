import { useRef } from 'react'
import { Trash2, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDropRuTtp, useRuTtpState, useUploadRuTtp } from '@/modules/attack/api/queries'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { moduleTitle } from '@/platform/modules'
import { BundleUpdate } from './BundleUpdate'

/**
 * Настройки модуля ATT&CK: сама матрица и применяемость техник в России.
 *
 * Матрица одна на все модули — на идентификаторы её техник ссылаются и
 * разметка правил SIEM, и техники VM с AD, — поэтому обновляет её
 * администратор; состояние видят все.
 */
export function AttackSettingsPage() {
  const { admin } = useCan()
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">{moduleTitle('attack')}</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Матрица одна на все модули: её обновление видят и покрытие правилами, и экспозиция.
          Файлы разбираются на месте и никуда не отправляются.
          {!admin && ' Матрицу обновляет администратор.'}
        </p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <section id="bundle">
          <BundleUpdate />
        </section>
        <RuTtpSource />
      </div>
    </div>
  )
}

/** Применяемость техник в России. Расхождение с миром — в разделе «РФ TTP». */
function RuTtpSource() {
  // Аудитору остаётся состояние выгрузки: какая, кем и когда загружена.
  const { write } = useCan()
  const state = useRuTtpState()
  const upload = useUploadRuTtp()
  const drop = useDropRuTtp()
  const inputRef = useRef<HTMLInputElement>(null)
  const source = state.data?.source ?? null
  const error = upload.isError
    ? upload.error instanceof ApiRequestError
      ? upload.error.message
      : 'Не удалось загрузить'
    : null

  return (
    <section id="ru-ttp" className="rounded border border-grid bg-surface p-4">
      <h2 className="mb-1 text-sm font-semibold text-text">Применяемость техник в России</h2>
      <p className="mb-3 max-w-3xl text-xs leading-relaxed text-text-secondary">
        Выгрузка «техника → процедура» — XLSX или CSV с идентификатором техники, процедурой,
        командной строкой и связями. Даёт вторую точку зрения рядом с мировой статистикой MITRE:
        в матрице появляется галочка «РФ», в карточке техники — процедуры с командами. В поставку
        такие данные не вкладываются — это чужая аналитика, и раздавать её продукт не вправе.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-text">
          {source ? (
            <>
              <span className="font-mono">{source.source}</span>
              <span className="text-text-secondary">
                {' '}
                — процедур: {source.row_count}, матрица {source.attack_version ?? '—'}
                {source.imported_by ? `, загрузил ${source.imported_by}` : ''}
                {source.imported_at ? `, ${new Date(source.imported_at).toLocaleString('ru')}` : ''}
              </span>
            </>
          ) : (
            <span className="text-text-secondary">Не загружена.</span>
          )}
        </span>
        {write && (
          <span className="ml-auto flex items-center gap-2">
            {/* input прячется, потому что его нельзя оформить. */}
            <input
              ref={inputRef}
              type="file"
              accept=".xlsx,.csv"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) upload.mutate(file)
                e.target.value = ''
              }}
            />
            <Button variant="primary" loading={upload.isPending} onClick={() => inputRef.current?.click()}>
              <Upload size={14} aria-hidden />
              {source ? 'Загрузить другую' : 'Загрузить выгрузку'}
            </Button>
            {source && (
              <Button variant="ghost" loading={drop.isPending} onClick={() => drop.mutate()}>
                <Trash2 size={14} aria-hidden />
                Убрать
              </Button>
            )}
          </span>
        )}
      </div>
      {error && <p className="mt-2 text-xs text-kind-1">{error}</p>}
    </section>
  )
}
