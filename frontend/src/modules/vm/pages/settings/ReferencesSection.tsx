import { useRef, useState } from 'react'
import { Download, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDownloadRef, useRefs, useUploadBundle, useUploadRef } from '@/modules/vm/api/queries'
import type { RefState } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'

const ABOUT: Record<string, string> = {
  epss: 'Вероятность эксплуатации за 30 дней от FIRST; без неё берётся априор из настроек (0.01) с пометкой.',
  nvd: 'Балл CVSS, метрики и описания CVE; фиды по годам, можно грузить частями.',
  exploitdb: 'Публичные эксплойты; тип эксплойта даёт вероятность p_exdb в члене L.',
  msf: 'Модули Metasploit; ранг модуля даёт вероятность p_msf в члене L.',
  kev: 'Каталог эксплуатируемых уязвимостей CISA; попадание — вероятность эксплуатации 1.0.',
}
const ACCEPT: Record<string, string> = { epss: '.csv,.gz', nvd: '.json,.gz', exploitdb: '.csv', msf: '.json', kev: '.json,.csv' }
const LINK = 'text-text underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const SOURCE: Record<string, string> = { network: 'сеть', file: 'файл', bundle: 'архив' }

function RefCard({ r }: { r: RefState }) {
  // Аудитору остаётся состояние справочника: что загружено, когда и откуда.
  const { write } = useCan()
  const download = useDownloadRef()
  const upload = useUploadRef()
  const inputRef = useRef<HTMLInputElement>(null)
  const thisYear = new Date().getFullYear()
  const [years, setYears] = useState(`${thisYear - 2}-${thisYear}`)
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
          {r.loaded_at ? `${new Date(r.loaded_at).toLocaleDateString('ru-RU')} · ${SOURCE[r.source ?? ''] ?? 'файл'}` : 'не загружен'}
          {r.stale && r.loaded_at && ' · устарел'}
        </span>
      </div>
      <p className="mb-2 text-[11px] text-text-secondary">{ABOUT[r.name]}</p>
      <div className="mb-2 font-mono text-[11px] tabular-nums text-text-secondary">
        {r.records ? `${r.records.toLocaleString('ru-RU')} записей` : '—'}{r.detail && ` · ${r.detail}`}
      </div>
      {write && r.name === 'nvd' && (
        <label className="mb-2 block text-[11px] text-text-secondary">
          <span>Годы для скачивания</span>
          <input className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 font-mono text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" value={years} onChange={(e) => setYears(e.target.value)} placeholder="2002-2026 или 2023, 2024" />
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {write && (
          <>
            <Button onClick={() => download.mutate({ name: r.name, years: r.name === 'nvd' ? parseYears() : undefined })} loading={download.isPending} disabled={busy} title={r.url}>
              <Download size={13} aria-hidden /> Скачать
            </Button>
            <Button onClick={() => inputRef.current?.click()} disabled={busy}>
              <Upload size={13} aria-hidden /> Загрузить файл
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
  // Скрипт для сети без интернета собирает все ленты в один zip; грузится он одной задачей.
  const { write } = useCan()
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
      <span>
        Для сети без интернета: скрипт собирает все справочники в один архив —{' '}
        <a className={LINK} href="/vm/download-references.ps1" download>Windows (PowerShell, прокси из системы)</a>
        {' · '}
        <a className={LINK} href="/vm/download-references.sh" download>Linux</a>
      </span>
      {write && (
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
      about="Скачиваются из сети или загружаются файлами — по одному или все сразу архивом. После загрузки витрина CVE пересобирается и риск пересчитывается. Старше 30 дней — помечается устаревшим."
    >
      <BundleUpload refs={refs.data ?? []} />
      <div className="grid gap-3 md:grid-cols-2">
        {(refs.data ?? []).map((r) => <RefCard key={r.name} r={r} />)}
      </div>
    </Section>
  )
}
