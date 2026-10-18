import type { Finding } from '@/modules/ksc/api/types'
import { CollectorFindingsTable, type FindingsTableProps } from '@/platform/collector/FindingsTable'
import type { ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'check_title', label: 'Проверка', width: 224 },
  { key: 'host', label: 'Хост', width: 208 },
  { key: 'target', label: 'Цель', width: 240, flex: true },
]

export function FindingsTable(props: FindingsTableProps<Finding>) {
  return (
    <CollectorFindingsTable
      {...props}
      storageKey="ksc-findings-columns"
      columns={COLUMNS}
      cells={(f) => (
        <>
          <div className="min-w-0 truncate px-2 text-text" title={f.check_title}>{f.check_title}</div>
          <div className="min-w-0 truncate px-2 font-mono text-text" title={f.host}>{f.host || '—'}</div>
          <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={f.target}>{f.target}</div>
        </>
      )}
    />
  )
}
