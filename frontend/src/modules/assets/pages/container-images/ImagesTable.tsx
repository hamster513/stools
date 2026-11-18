import { ChevronRight } from 'lucide-react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { RegistryBadge } from './RegistryBadge'
import { SOURCES, STATES, sizeText, when, type Image } from './types'

const COLUMNS: ColumnDef[] = [
  { key: 'title', label: 'Образ', width: 240, flex: true },
  { key: 'tags', label: 'Теги', width: 96 },
  { key: 'source', label: 'Источник', width: 112 },
  { key: 'registry', label: 'Реестр', width: 152 },
  { key: 'status', label: 'Использование', width: 168 },
  { key: 'hosts', label: 'Хостов', width: 72, align: 'right' },
  { key: 'containers', label: 'Контейнеров', width: 104, align: 'right' },
  { key: 'hash', label: 'Хеш / ID', width: 168 },
  { key: 'platform', label: 'Платформа', width: 120 },
  { key: 'size', label: 'Размер', width: 88, align: 'right' },
  { key: 'collected', label: 'Получено', width: 104 },
  { key: 'open', label: 'Открыть', width: 32, resizable: false },
]

export function ImagesTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd }: {
  items: Image[]; selectedIndex: number; onSelectIndex: (index: number) => void;
  onOpen: (image: Image) => void; onReachEnd?: () => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, 40, selectedIndex, onReachEnd)
  const cols = useColumnWidths('assets-container-images-columns', COLUMNS)
  return <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
    <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
      <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ open: <span className="sr-only">Открыть</span> }} />
    </div>
    <div style={{ height: totalSize, position: 'relative' }}>
      {rows.map((v) => {
        const image = items[v.index]
        const external = image.registry_origin === 'external' || image.registry_origin === 'mixed'
        return <div key={`${image.source}:${image.id}`} {...clickableRow(() => { onSelectIndex(v.index); onOpen(image) })}
          className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selectedIndex === v.index ? 'bg-row-selected' : external ? 'bg-risk-medium/5 hover:bg-risk-medium/10' : 'hover:bg-row-hover')}
          style={{ ...cols.gridStyle, height: 40, transform: `translateY(${v.start}px)` }}>
          {external && <span className="absolute inset-y-0 left-0 w-0.5 bg-risk-medium" aria-hidden />}
          <div className="min-w-0 truncate px-2 font-mono text-text" title={image.display_title || image.title}>{image.display_title || image.title}</div>
          <div className="min-w-0 truncate px-2 text-text-secondary" title={image.tags.join(', ')}>{image.tags.join(', ') || '—'}</div>
          <div className="min-w-0 truncate px-2 text-text-secondary">{SOURCES[image.source]}</div>
          <div className="min-w-0 px-2"><RegistryBadge origin={image.registry_origin} external={image.external_registries} /></div>
          <div className="min-w-0 truncate px-2 text-text-secondary" title={image.source === 'harbor' ? 'В реестре' : STATES[image.status]}>{image.source === 'harbor' ? 'В реестре' : STATES[image.status]}</div>
          <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{image.host_count ?? '—'}</div>
          <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{image.container_count ?? '—'}</div>
          <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={image.image_id}>{image.image_id || 'Не определён'}</div>
          <div className="min-w-0 truncate px-2 text-text-secondary" title={image.platform ?? ''}>{image.platform || '—'}</div>
          <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary" title={sizeText(image.size)}>{sizeText(image.size)}</div>
          <div className="min-w-0 truncate px-2 text-text-secondary" title={when(image.collected_at)}>{new Date(image.collected_at).toLocaleDateString('ru-RU')}</div>
          <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
        </div>
      })}
    </div>
  </div>
}
