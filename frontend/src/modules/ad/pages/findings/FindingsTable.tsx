import type { Finding } from '@/modules/ad/api/types'
import { CollectorFindingsTable, type FindingsTableProps } from '@/platform/collector/FindingsTable'
import type { ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'check_title', label: 'Проверка', width: 208 },
  { key: 'identity', label: 'Identity', width: 224 },
  { key: 'target', label: 'Цель', width: 240, flex: true },
  { key: 'detail', label: 'Право / детали', width: 192 },
]

function detailOf(f: Finding): string {
  return f.right || (typeof f.details.details === 'string' ? f.details.details : '') || (typeof f.details.delegation_type === 'string' ? f.details.delegation_type : '')
}

export function FindingsTable(props: FindingsTableProps<Finding>) {
  return (
    <CollectorFindingsTable
      {...props}
      storageKey="ad-findings-columns"
      columns={COLUMNS}
      cells={(f) => {
        const detail = detailOf(f)
        return (
          <>
            <div className="min-w-0 truncate px-2 text-text" title={f.check_title}>{f.check_title}</div>
            <div className="min-w-0 truncate px-2 font-mono text-text" title={f.identity}>{f.identity || '—'}</div>
            <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={f.target}>{f.target}</div>
            <div className="min-w-0 truncate px-2 text-text-secondary" title={detail}>{detail}</div>
          </>
        )
      }}
    />
  )
}
