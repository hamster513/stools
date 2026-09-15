import { Globe, MapPin, TriangleAlert } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRuTtpState } from '@/modules/attack/api/queries'
import { ruWords, type RuTechniqueItem } from '@/modules/attack/api/types'
import { Link } from '@/lib/router'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'

/**
 * Применяемость техник здесь рядом с мировыми данными MITRE.
 *
 * Два источника меряют разное. MITRE считает, сколько мировых группировок
 * и кампаний применяют технику; выгрузка показывает, что видели здесь.
 * Складывать их в один балл нельзя — тогда непонятно, чем поднята строка.
 *
 * Состояний четыре, а не два. «Нет у источника» означает «источник об этом
 * не отчитывался», а не «не применяют», и делить мир надвое было бы
 * неправдой. Ценность экрана — ровно в двух списках расхождений.
 */
export function RuTtpPage() {
  const state = useRuTtpState()

  if (state.isLoading) return <FullPageSpinner />
  if (state.isError || !state.data) {
    const message =
      state.error instanceof ApiRequestError ? state.error.message : 'Не удалось загрузить слой'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => state.refetch()} />
      </div>
    )
  }

  const data = state.data

  if (!data.source) {
    return (
      <div className="m-6 flex flex-col items-start gap-3 rounded border border-dashed border-grid p-6">
        <p className="max-w-2xl text-sm text-text">
          Мировая статистика MITRE считает, сколько группировок и кампаний применяют технику
          где угодно. Для вашей инфраструктуры этот вес смещён: техника, которой в мировых
          данных нет вовсе, может быть рабочим инструментом тех, кто ходит именно сюда.
        </p>
        <p className="max-w-2xl text-xs text-text-secondary">
          Выгрузка «техника → процедура» загружается в настройках, вместе с остальными
          файлами продукта.
        </p>
        <Link
          to="/attack/settings"
          className="text-sm text-primary underline underline-offset-2 hover:text-text"
        >
          Настройки и данные →
        </Link>
      </div>
    )
  }

  const counts = data.counts
  return (
    <div className="flex h-full min-h-0 flex-col gap-3 overflow-y-auto p-6">
      <div>
        <h1 className="text-base font-semibold text-text">Применяемость техник здесь</h1>
        <p className="max-w-3xl text-xs text-text-secondary">
          Загруженная выгрузка рядом с мировой статистикой MITRE. Ценность экрана — в двух
          списках расхождений, а не в общем балле.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-3 rounded border border-grid bg-surface px-3 py-2.5 text-xs">
        <span className="text-text">
          <span className="font-mono">{data.source.source}</span> — {data.source.row_count} процедур
        </span>
        {data.source.imported_by && (
          <span className="text-text-secondary">
            загрузил {data.source.imported_by}
            {data.source.imported_at
              ? `, ${new Date(data.source.imported_at).toLocaleString('ru')}`
              : ''}
          </span>
        )}
        <span className="text-text-secondary">матрица {data.attack_version}</span>
        <Link
          to="/attack/settings"
          className="ml-auto text-text-secondary underline underline-offset-2 hover:text-primary"
        >
          заменить или убрать — в настройках
        </Link>
      </div>

      {/* Тактики — единственное, что из файла осознанно не берётся, и
          сказать об этом надо на экране, а не только в коде. */}
      <p className="text-xs text-text-secondary">
        Тактики и порядок шагов взяты из матрицы MITRE {data.attack_version}: в выгрузке они
        те же самые, и хранить вторую копию значило бы разойтись с матрицей при её обновлении.
        Совпадение считается по идентификатору техники; разметка родителем закрывает подтехнику,
        соседняя подтехника — нет.
      </p>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Count
          label="И здесь, и в мире"
          value={counts.both ?? 0}
          hint="Оба источника видели технику — вес мировой статистики здесь уместен"
        />
        <Count
          label="Только здесь"
          value={counts.ru_only ?? 0}
          hint="Мировая статистика молчит: без выгрузки продукт показывал эти техники как «в мире не применяют»"
          tone="text-kind-2"
        />
        <Count
          label="Только в мире"
          value={counts.world_only ?? 0}
          hint="В выгрузке их нет. Это значит «выгрузка об этом не отчитывалась», а не «здесь не применяют»"
        />
        <Count
          label="Нет нигде"
          value={counts.none ?? 0}
          hint="Ни один источник не видел технику — судить о ней по этим данным нельзя"
        />
      </div>

      {data.unknown.length > 0 && (
        <div className="flex gap-2 rounded border border-kind-3/40 bg-kind-3/5 px-3 py-2 text-xs leading-relaxed text-text-secondary">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-kind-3" aria-hidden />
          <div>
            Техник из выгрузки нет в матрице {data.attack_version} и замены им не нашлось:{' '}
            <span className="font-mono text-text">{data.unknown.join(', ')}</span>. Это расхождение
            версий, а не мусор: выгрузка сделана на другой матрице.
          </div>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <List
          icon={<MapPin className="h-3.5 w-3.5 text-kind-2" aria-hidden />}
          title="Замечено здесь, мировая статистика молчит"
          note="Вес этих техник продукт занижал: в мировых данных у них ноль группировок и ноль кампаний."
          items={data.ru_only}
          right={(i) => (i.ru ? `${i.ru.actors} гр. · ${i.ru.procedures} проц.` : '')}
        />
        <List
          icon={<Globe className="h-3.5 w-3.5 text-text-secondary" aria-hidden />}
          title="Мир видит, в выгрузке нет"
          note="Не «здесь не применяют», а «выгрузка об этом не отчитывалась». Мировой вес остаётся в силе."
          items={data.world_only}
          right={(i) => `${i.world_groups} гр. в мире`}
        />
      </div>
    </div>
  )
}

function Count({
  label,
  value,
  hint,
  tone = 'text-text',
}: {
  label: string
  value: number
  hint: string
  tone?: string
}) {
  return (
    <div className="rounded border border-grid bg-surface px-3 py-2.5" title={hint}>
      <div className="text-xs text-text-secondary">{label}</div>
      <div className={`mt-0.5 font-mono text-lg ${tone}`}>{value}</div>
    </div>
  )
}

function List({
  icon,
  title,
  note,
  items,
  right,
}: {
  icon: React.ReactNode
  title: string
  note: string
  items: RuTechniqueItem[]
  right: (item: RuTechniqueItem) => string
}) {
  return (
    <section className="rounded border border-grid bg-surface p-3">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold text-text">
        {icon}
        {title}
        <span className="font-mono text-xs text-text-secondary">{items.length}</span>
      </h3>
      <p className="mt-1 mb-2 text-[11px] leading-relaxed text-text-secondary">{note}</p>
      {items.length === 0 ? (
        <p className="text-xs text-text-secondary">Расхождений нет.</p>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {items.map((item) => (
            <li
              key={item.technique_id}
              className="flex items-baseline gap-2 rounded px-1 py-0.5 text-xs"
              title={item.ru ? ruWords(item.ru) : undefined}
            >
              <span className="font-mono text-text-secondary">{item.technique_id}</span>
              <span className="min-w-0 truncate text-text">{item.name}</span>
              <span className="ml-auto shrink-0 whitespace-nowrap text-[11px] text-text-secondary">
                {right(item)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
