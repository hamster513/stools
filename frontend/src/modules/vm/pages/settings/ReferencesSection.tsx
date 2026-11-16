import { useRef, useState } from 'react'
import { Download, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDownloadRef, useRefs, useUploadBundle, useUploadRef } from '@/modules/vm/api/queries'
import type { RefDownloadMode, RefState } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'

const ABOUT: Record<string, string> = {
  ghsa: 'GitHub Advisory Database: GHSA, связи с CVE, пакеты и диапазоны версий. Включает уязвимости без CVE; ZIP официального репозитория.',
  epss: 'Вероятность эксплуатации за 30 дней от FIRST; в скоринге даёт 2–30 баллов. Если EPSS нет — 8 баллов; эксплойт или KEV может дать больше.',
  nvd: 'Балл CVSS, метрики и описания CVE; фиды по годам, можно грузить частями.',
  exploitdb: 'Публичные эксплойты; наличие даёт 24 балла в блоке эксплуатации, если нет более сильного сигнала.',
  msf: 'Модули Metasploit: 24 балла, готовые good/great/excellent — 32. В блоке эксплуатации учитывается самый сильный сигнал.',
  kev: 'Каталог эксплуатируемых уязвимостей CISA: 40 баллов в блоке эксплуатации и итоговый приоритет не ниже High (80).',
}
const ACCEPT: Record<string, string> = { ghsa: '.zip', epss: '.csv,.gz', nvd: '.json,.gz', exploitdb: '.csv', msf: '.json', kev: '.json,.csv' }
const LINK = 'text-text underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const SOURCE: Record<string, string> = { network: 'сеть', file: 'файл', bundle: 'архив' }

function RefCard({ r }: { r: RefState }) {
  // Аудитору остаётся состояние справочника: что загружено, когда и откуда.
  const { admin } = useCan()
  const download = useDownloadRef()
  const upload = useUploadRef()
  const inputRef = useRef<HTMLInputElement>(null)
  const thisYear = new Date().getFullYear()
  const [years, setYears] = useState(`2002-${thisYear}`)
  const [mode, setMode] = useState<RefDownloadMode>('auto')
  const fullDownload = mode === 'full' || (mode === 'auto' && !r.loaded_at)
  const unavailable = mode === 'updates' && !r.update_available
  const busy = r.active_job_id !== null || download.isPending || upload.isPending

  function parseYears(): number[] | undefined {
    const m = years.match(/^(\d{4})\s*-\s*(\d{4})$/)
    if (m) {
      const [a, b] = [Number(m[1]), Number(m[2])]
      return Array.from({ length: b - a + 1 }, (_, i) => a + i)
    }
    const list = years.split(/[,\s]+/).map(Number).filter((y) => y >= 1999)
    return list.length ? list : undefined
  }
  const error = download.error ?? upload.error
  const errorText = error instanceof ApiRequestError ? error.message : error ? 'Не удалось запустить' : null

  return (
    <div className="rounded border border-grid bg-app-bg p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-sm font-medium text-text">{r.title}</span>
        <span className={cn('text-[11px]', r.stale ? 'text-risk-medium' : 'text-text-secondary')}>
          {r.loaded_at ? `${new Date(r.loaded_at).toLocaleDateString('ru-RU')} · ${r.partial_window ? 'частичное обновление' : SOURCE[r.source ?? ''] ?? 'файл'}` : 'не загружен'}
          {r.stale && r.loaded_at && ' · устарел'}
        </span>
      </div>
      <p className="mb-2 text-[11px] text-text-secondary">{ABOUT[r.name]}</p>
      <div className="mb-2 font-mono text-[11px] tabular-nums text-text-secondary">
        {r.records ? `${r.records.toLocaleString('ru-RU')} записей` : '—'}{r.detail && ` · ${r.detail}`}
      </div>
      {r.partial_window && <p className="mb-2 text-[11px] text-risk-medium">
        Изменения за {new Date(r.partial_window.since).toLocaleString('ru-RU')} — {new Date(r.partial_window.until).toLocaleString('ru-RU')}.
        {' '}Полнота базы за остальные даты не подтверждена.
        {!r.last_checked_at && ' Дата последней полной проверки неизвестна.'}
      </p>}
      {r.last_checked_at && <p className="mb-2 text-[11px] text-text-secondary">
        {r.partial_window ? 'Последняя полная проверка' : 'Проверено'}: {new Date(r.last_checked_at).toLocaleString('ru-RU')}
        {r.last_mode === 'unchanged' ? <span className="ml-2 text-risk-low">Обновлений нет</span> : r.last_counts && <span> · Применено: {r.last_counts.upserted.toLocaleString('ru-RU')} · Удалено: {r.last_counts.deleted.toLocaleString('ru-RU')}</span>}
      </p>}
      {r.pending_rebuild && <p className="mb-2 text-[11px] text-risk-medium">Ожидается пересчёт риска по обновлённой базе.</p>}
      {admin && <label className="mb-2 block text-[11px] text-text-secondary">
        <span>Режим загрузки</span>
        <select aria-label={`Режим загрузки: ${r.title}`} className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" value={mode} onChange={e => setMode(e.target.value as RefDownloadMode)} disabled={busy}>
          <option value="auto">Автоматически</option>
          <option value="updates" disabled={!r.update_available}>Только обновления</option>
          <option value="full">Полная загрузка</option>
        </select>
      </label>}
      <p className="mb-2 text-[11px] text-text-secondary">{r.update_capability === 'delta' ? 'Получаем новые и изменённые записи, сохраняя остальную базу.' : 'Проверяем версию источника. При изменении загружается новый снимок: источник не предоставляет отдельные записи обновлений.'}</p>
      {r.update_reason && <p className="mb-2 text-[11px] text-risk-medium">{r.update_reason}</p>}
      {admin && r.name === 'nvd' && fullDownload && (
        <label className="mb-2 block text-[11px] text-text-secondary">
          <span>Годы для скачивания</span>
          <input className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 font-mono text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" value={years} onChange={(e) => setYears(e.target.value)} placeholder="2002-2026 или 2023, 2024" />
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {admin && (
          <>
            <Button onClick={() => download.mutate({ name: r.name, mode, years: r.name === 'nvd' && fullDownload ? parseYears() : undefined })} loading={download.isPending} disabled={busy || unavailable} title={r.url}>
              <Download size={13} aria-hidden /> {fullDownload ? 'Скачать базу' : 'Проверить обновления'}
            </Button>
            <Button onClick={() => inputRef.current?.click()} disabled={busy}>
              <Upload size={13} aria-hidden /> Загрузить полный файл
            </Button>
            <input ref={inputRef} type="file" accept={ACCEPT[r.name]} multiple={r.name === 'nvd'} className="hidden" onChange={(e) => { const files = Array.from(e.target.files ?? []); if (files.length) upload.mutate({ name: r.name, files }); e.target.value = '' }} />
          </>
        )}
        {r.active_job_id !== null && <span className="text-[11px] text-text-secondary">идёт задача #{r.active_job_id}</span>}
        {errorText && <span className="text-[11px] text-kind-1">{errorText}</span>}
      </div>
    </div>
  )
}

function BundleUpload({ refs }: { refs: RefState[] }) {
  // Полные снимки и пакеты обновлений загружаются через одну точку входа.
  const { admin } = useCan()
  const upload = useUploadBundle()
  const inputRef = useRef<HTMLInputElement>(null)
  // Задача архива занимает все справочники сразу: у каждой карточки один и тот же номер.
  // Так она и отличается от задачи одной карточки, без отдельного запроса списка задач.
  const ids = new Set(refs.map((r) => r.active_job_id))
  const bundleJob = refs.length > 1 && ids.size === 1 ? refs[0].active_job_id : null
  const busy = refs.some((r) => r.active_job_id !== null) || upload.isPending
  const error = upload.error
  const errorText = error instanceof ApiRequestError ? error.message : error ? 'Не удалось запустить' : null

  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-text-secondary">
      <div className="w-full space-y-2">
        <p>Для закрытого контура: <a className={LINK} href="/offline/stools-download-kit.zip" download>Единый загрузчик — Linux и PowerShell</a></p>
        <details><summary className="cursor-pointer">Полная выгрузка и обновления за период</summary>
          <ol className="mt-2 list-inside list-decimal space-y-1">
            <li>Распакуйте комплект на компьютере с интернетом. Нужен Python 3.11+, для обновлений GHSA и правил — Git.</li>
            <li>Запустите без параметров для меню: выберите данные, полный режим или изменения за день, неделю либо три календарных месяца.</li>
            <li>Самостоятельно проверьте давность баз в STools: скрипт выгрузит ровно выбранный период.</li>
            <li>Архивы справочников загрузите здесь, архивы новостей и правил — в блоке «Архив новостей».</li>
          </ol>
          <p className="mt-2">Linux:</p><code className="mt-1 block break-all rounded bg-app-bg p-2">sh download-stools.sh --datasets nvd,ghsa --mode updates --period 7d --lang ru --quiet</code>
          <p className="mt-2">PowerShell:</p><code className="mt-1 block break-all rounded bg-app-bg p-2">.\download-stools.ps1 -Datasets nvd,ghsa -Mode Updates -Period 7d -Lang ru -Quiet</code>
          <p className="mt-2">Файл состояния STools не нужен. Частичный импорт не подтверждает актуальность всей базы. Прокси используется из системы; язык меню — русский или английский.</p>
        </details>
      </div>
      {admin && (
        <>
          <Button onClick={() => inputRef.current?.click()} loading={upload.isPending} disabled={busy}>
            <Upload size={13} aria-hidden /> Загрузить архив
          </Button>
          <input ref={inputRef} type="file" accept=".zip" className="hidden" onChange={(e) => { const file = e.target.files?.[0]; if (file) upload.mutate(file); e.target.value = '' }} />
        </>
      )}
      {bundleJob !== null && <span className="text-[11px]">идёт задача #{bundleJob}</span>}
      {errorText && <span className="text-[11px] text-kind-1">{errorText}</span>}
    </div>
  )
}

export function ReferencesSection() {
  const refs = useRefs()
  return (
    <Section
      id="references"
      title="Справочники"
      about="Скачиваются из сети или загружаются файлами — по одному или все сразу архивом. В автоматическом режиме загружаются обновления, а пустая база — целиком. По расписанию используется тот же режим. После изменений риск пересчитывается; если обновлений нет, данные сохраняются."
    >
      <BundleUpload refs={refs.data ?? []} />
      <div className="grid gap-3 md:grid-cols-2">
        {(refs.data ?? []).map((r) => <RefCard key={r.name} r={r} />)}
      </div>
    </Section>
  )
}
