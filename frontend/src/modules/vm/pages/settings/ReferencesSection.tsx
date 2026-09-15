import { useRef, useState } from 'react'
import { Download, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDownloadRef, useRefs, useUploadRef } from '@/modules/vm/api/queries'
import type { RefState } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from './ui'

const ABOUT: Record<string, string> = {
  epss: 'Вероятность эксплуатации за 30 дней от FIRST; без неё берётся 0.5.',
  nvd: 'Балл CVSS, метрики и описания CVE; фиды по годам, можно грузить частями.',
  exploitdb: 'Публичные эксплойты; тип эксплойта — множитель ExDB_param.',
  msf: 'Модули Metasploit; ранг модуля — множитель MSF_param.',
}
const ACCEPT: Record<string, string> = { epss: '.csv,.gz', nvd: '.json,.gz', exploitdb: '.csv', msf: '.json' }

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
          {r.loaded_at ? `${new Date(r.loaded_at).toLocaleDateString('ru-RU')} · ${r.source === 'network' ? 'сеть' : 'файл'}` : 'не загружен'}
          {r.stale && r.loaded_at && ' · устарел'}
        </span>
      </div>
      <p className="mb-2 text-[11px] text-text-secondary">{ABOUT[r.name]}</p>
      <div className="mb-2 font-mono text-[11px] tabular-nums text-text-secondary">
        {r.records ? `${r.records.toLocaleString('ru-RU')} записей` : '—'}{r.detail && ` · ${r.detail}`}
      </div>
      {write && r.name === 'nvd' && (
        <label className="mb-2 block text-[11px] text-text-secondary">
          Годы для скачивания
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

export function ReferencesSection() {
  const refs = useRefs()
  return (
    <Section
      title="Справочники"
      about="Скачиваются из сети или загружаются файлами (для сетей без интернета есть скрипт docs/vm/download-references.sh). После загрузки витрина CVE пересобирается и риск пересчитывается. Старше 30 дней — помечается устаревшим."
    >
      <div className="grid gap-3 md:grid-cols-2">
        {(refs.data ?? []).map((r) => <RefCard key={r.name} r={r} />)}
      </div>
    </Section>
  )
}
