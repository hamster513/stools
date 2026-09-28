import type { Finding } from '@/modules/ksc/api/types'
import { CollectorFindingsTable, type FindingsTableProps } from '@/platform/collector/FindingsTable'

export function FindingsTable(props: FindingsTableProps<Finding>) {
  return (
    <CollectorFindingsTable
      {...props}
      minWidth="min-w-[900px]"
      head={
        <>
          <div className="w-56 shrink-0 px-2 py-2">Проверка</div>
          <div className="w-52 shrink-0 px-2 py-2">Хост</div>
          <div className="min-w-[240px] flex-1 px-2 py-2">Цель</div>
        </>
      }
      cells={(f) => (
        <>
          <div className="w-56 shrink-0 truncate px-2 text-text" title={f.check_title}>{f.check_title}</div>
          <div className="w-52 shrink-0 truncate px-2 font-mono text-text" title={f.host}>{f.host || '—'}</div>
          <div className="min-w-[240px] flex-1 truncate px-2 font-mono text-text-secondary" title={f.target}>{f.target}</div>
        </>
      )}
    />
  )
}
