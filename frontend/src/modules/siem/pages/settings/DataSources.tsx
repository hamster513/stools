import { useRef } from 'react'
import { Trash2, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useDropReference,
  useReferenceCompare,
  useSnapshots,
  useUploadReference,
} from '@/modules/siem/api/queries'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { KbSource } from './KbSource'
import { SnapshotUpload } from './SnapshotUpload'

/**
 * Все файлы продукта в одном месте.
 *
 * Раньше их загружали из четырёх разных экранов, и человек, которому надо
 * что-то обновить, вспоминал, какой файл в каком разделе. Загрузка — это
 * настройка инструмента, и место у неё одно.
 *
 * Разбор загруженного при этом остаётся там, где им пользуются: сверка с
 * эталоном и списки расхождений живут на экране покрытия. Гонять человека
 * в настройки, чтобы посмотреть результат, — та же ошибка наоборот.
 *
 * Матрица и выгрузка РФ TTP отсюда ушли: они общие для всех модулей.
 * Матрицу обновляет администратор в общих настройках, выгрузку РФ TTP
 * загружают в модуле ATT&CK. Оставить их копию здесь значило бы завести
 * второе место, где то же самое обновляется по-другому.
 */
export function DataSources() {
  // Аудитору загружать нечем: сервер ответит 403. Рамка с полем для файла
  // у него — обещание, которого продукт не выполнит.
  const { write } = useCan()
  return (
    <>
      <KbSource />
      {write && <SnapshotUpload />}
      <ReferenceSource />
      <p className="text-xs text-text-secondary">
        База ATT&amp;CK — в общих настройках:{' '}
        <Link to="/settings/attack" className="underline underline-offset-2 hover:text-primary">
          обновление матрицы
        </Link>
        . Выгрузка РФ TTP — в модуле ATT&amp;CK:{' '}
        <Link to="/attack/settings" className="underline underline-offset-2 hover:text-primary">
          применяемость техник здесь
        </Link>
        .
      </p>
    </>
  )
}

/** Общая рамка: у всех источников одна форма — что это, что загружено, что можно. */
function Source({
  title,
  about,
  state,
  actions,
  error,
}: {
  title: string
  about: React.ReactNode
  state: React.ReactNode
  actions: React.ReactNode
  error?: string | null
}) {
  return (
    <section className="rounded border border-grid bg-surface p-4">
      <h2 className="mb-1 text-sm font-semibold text-text">{title}</h2>
      <p className="mb-3 max-w-3xl text-xs leading-relaxed text-text-secondary">{about}</p>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-text">{state}</span>
        <span className="ml-auto flex items-center gap-2">{actions}</span>
      </div>
      {error && <p className="mt-2 text-xs text-kind-1">{error}</p>}
    </section>
  )
}

/** Кнопка выбора файла: input прячется, потому что его нельзя оформить. */
function Picker({
  label,
  accept,
  busy,
  onPick,
}: {
  label: string
  accept: string
  busy: boolean
  onPick: (file: File) => void
}) {
  const ref = useRef<HTMLInputElement>(null)
  return (
    <>
      <input
        ref={ref}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0]
          if (file) onPick(file)
          e.target.value = ''
        }}
      />
      <Button variant="primary" loading={busy} onClick={() => ref.current?.click()}>
        <Upload size={14} aria-hidden />
        {label}
      </Button>
    </>
  )
}

function Loaded({
  source,
  by,
  at,
  extra,
}: {
  source: string
  by: string | null
  at: string | null
  extra?: string
}) {
  return (
    <>
      <span className="font-mono">{source}</span>
      {extra && <span className="text-text-secondary"> — {extra}</span>}
      {by && (
        <span className="text-text-secondary">
          , загрузил {by}
          {at ? `, ${new Date(at).toLocaleString('ru')}` : ''}
        </span>
      )}
    </>
  )
}

/** Эталонная разметка. Сверка с ней — на экране покрытия. */
function ReferenceSource() {
  // Сверка привязана к снапшоту, а настройки открываются и без него:
  // до первой выгрузки эталону не с чем сверяться, и это надо сказать.
  const { write } = useCan()
  const snapshots = useSnapshots()
  const latest = snapshots.data?.reduce((a, b) => (b.id > a.id ? b : a), snapshots.data[0])
  const compare = useReferenceCompare(latest?.id)
  const upload = useUploadReference(latest?.id ?? 0)
  const drop = useDropReference()
  const data = compare.data

  return (
    <Source
      title="Эталонная разметка"
      about={
        <>
          Ваша таблица «правило → техника ATT&amp;CK» — XLSX или CSV. Продукт ею свою разметку не
          подменяет: ценность в разнице, и она видна на экране покрытия, во вкладке «Сверка с
          эталоном». Правила сопоставляются по коду, так что различие в префиксе помехой не будет.{' '}
          <a
            href="/samples/attack-reference-sample.csv"
            download
            className="text-primary underline underline-offset-2 hover:text-text"
          >
            Скачать образец
          </a>{' '}
          для заполнения.
        </>
      }
      state={
        !latest ? (
          <span className="text-text-secondary">
            Сначала нужна выгрузка правил — сверять эталон пока не с чем.
          </span>
        ) : data?.loaded ? (
          <Loaded
            source={data.source ?? 'файл'}
            by={data.imported_by}
            at={data.imported_at}
            extra={`сверено правил: ${data.compared}`}
          />
        ) : (
          <span className="text-text-secondary">Не загружена.</span>
        )
      }
      actions={
        // Аудитору остаётся состояние источника: что загружено и кем.
        write ? (
          <>
            {latest && (
              <Picker
                label={data?.loaded ? 'Загрузить другую' : 'Загрузить таблицу'}
                accept=".xlsx,.csv"
                busy={upload.isPending}
                onPick={(file) => upload.mutate(file)}
              />
            )}
            {data?.loaded && (
              <Button variant="ghost" loading={drop.isPending} onClick={() => drop.mutate()}>
                <Trash2 size={14} aria-hidden />
                Убрать
              </Button>
            )}
          </>
        ) : null
      }
      error={
        upload.isError
          ? upload.error instanceof ApiRequestError
            ? upload.error.message
            : 'Не удалось загрузить'
          : null
      }
    />
  )
}
