import type { Finding } from '@/modules/ad/api/types'
import { CollectorFindingsTable, type FindingsTableProps } from '@/platform/collector/FindingsTable'

function detailOf(f: Finding): string {
  return f.right || (typeof f.details.details === 'string' ? f.details.details : '') || (typeof f.details.delegation_type === 'string' ? f.details.delegation_type : '')
}

export function FindingsTable(props: FindingsTableProps<Finding>) {
  return (
    <CollectorFindingsTable
      {...props}
      minWidth="min-w-[1100px]"
      head={
        <>
          <div className="w-52 shrink-0 px-2 py-2">Проверка</div>
          <div className="w-56 shrink-0 px-2 py-2">Identity</div>
          <div className="min-w-[240px] flex-1 px-2 py-2">Цель</div>
          <div className="w-48 shrink-0 px-2 py-2">Право / детали</div>
        </>
      }
      cells={(f) => {
        const detail = detailOf(f)
        return (
          <>
            <div className="w-52 shrink-0 truncate px-2 text-text" title={f.check_title}>{f.check_title}</div>
            <div className="w-56 shrink-0 truncate px-2 font-mono text-text" title={f.identity}>{f.identity || '—'}</div>
            <div className="min-w-[240px] flex-1 truncate px-2 font-mono text-text-secondary" title={f.target}>{f.target}</div>
            <div className="w-48 shrink-0 truncate px-2 text-text-secondary" title={detail}>{detail}</div>
          </>
        )
      }}
    />
  )
}
