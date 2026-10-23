import { useEffect, useState } from 'react'
import { Network as NetworkIcon, Plus, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDeleteNetwork, useNetwork, useNetworks } from '@/modules/assets/api/queries'
import type { NetworkItem } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { NetworkForm } from './NetworkForm'

const COLUMNS: ColumnDef[] = [
  { key: 'cidr', label: 'CIDR', width: 136 },
  { key: 'title', label: 'Название', width: 96, flex: true },
  { key: 'zone', label: 'Зона', width: 80 },
  { key: 'site', label: 'Площадка', width: 96 },
  { key: 'assets', label: 'Активов', width: 84, align: 'right' },
]
// Кнопки только у тех, кому можно менять: без них пустая колонка не занимает места.
const WRITE_COLUMNS: ColumnDef[] = [...COLUMNS, { key: 'actions', label: 'Действие', width: 112, resizable: false }]
const HEADER = {
  actions: <span className="sr-only">Действие</span>,
}

function ConfirmDelete({ network, onDone }: { network: NetworkItem; onDone: () => void }) {
  const remove = useDeleteNetwork()
  return (
    <div role="dialog" aria-label="Удалить сеть" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">Удалить сеть {network.cidr}?</div>
        <p className="mb-4 text-xs text-text-secondary">
          Активы сети ({network.assets}) перейдут в самую узкую из оставшихся сетей, содержащую их адрес, или останутся без сети;
          привязка вручную к этой сети сбрасывается.
        </p>
        {remove.error && <p className="mb-2 text-xs text-kind-1">{remove.error instanceof ApiRequestError ? remove.error.message : 'Не удалось удалить'}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onDone}>Отмена</Button>
          <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(network.id, { onSuccess: onDone })}>Удалить</Button>
        </div>
      </div>
    </div>
  )
}

/** Правка сети: поля формы — из карточки (в строке списка нет описания и владельца). */
function EditNetwork({ id, onDone }: { id: number; onDone: () => void }) {
  const card = useNetwork(id)
  if (card.isError) return <ErrorState message={card.error instanceof ApiRequestError ? card.error.message : 'Не удалось загрузить сеть'} onRetry={() => card.refetch()} />
  if (!card.data) return <FullPageSpinner />
  return <NetworkForm network={card.data} onDone={onDone} onCancel={onDone} />
}

/** Сети: CIDR, зона, площадка, сколько активов. Строка — правка сети. */
export function NetworksPage() {
  const { write } = useCan()
  const networks = useNetworks()
  // `?new=<cidr>` — ссылка «создать сеть» из карточки актива без сети: форма новой сети открыта сразу, CIDR подставлен.
  const params = useSearchParams()
  const { navigate } = useRouter()
  const [newCidr, setNewCidr] = useState(() => params.get('new') ?? '')
  // undefined — форма закрыта, null — новая сеть, число — id изменяемой сети.
  const [editing, setEditing] = useState<number | null | undefined>(() => (newCidr ? null : undefined))
  // Параметр снимается: закрытая форма не откроется снова при обновлении страницы.
  useEffect(() => { if (params.has('new')) navigate('/assets/networks', { replace: true }) }, [params, navigate])
  function closeForm() { setEditing(undefined); setNewCidr('') }
  const [deleting, setDeleting] = useState<NetworkItem | null>(null)
  const cols = useColumnWidths('assets-networks-columns', write ? WRITE_COLUMNS : COLUMNS)

  if (networks.isLoading) return <FullPageSpinner />
  if (networks.isError || !networks.data) {
    const msg = networks.error instanceof ApiRequestError ? networks.error.message : 'Не удалось загрузить сети'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => networks.refetch()} /></div>
  }
  const list = networks.data.items

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Сети</h1>
            <ExportButton href={(fmt) => `/api/assets/networks/export?format=${fmt}`} total={networks.data.total} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Актив привязывается к самой узкой сети, содержащей его адрес; в карточке актива сеть можно задать вручную. Пересечение сетей допустимо.
          </p>
        </div>
        {write && editing === undefined && <Button className="ml-auto shrink-0" onClick={() => setEditing(null)}><Plus size={13} aria-hidden /> Добавить сеть</Button>}
      </div>

      {editing !== undefined && (
        <div className="mb-4">
          {editing === null
            ? <NetworkForm key="new" network={null} initialCidr={newCidr} onDone={closeForm} onCancel={closeForm} />
            : <EditNetwork key={editing} id={editing} onDone={closeForm} />}
        </div>
      )}

      {list.length === 0 ? (
        <EmptyState icon={NetworkIcon} title="Сетей ещё нет" description="Опишите сети с зоной и площадкой: активы привяжутся к ним по адресу." />
      ) : (
        <div className="overflow-x-auto rounded border border-grid bg-surface">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
              <tr className="border-b border-grid">
                <ResizableHeader cols={cols} className="px-3 py-2" content={HEADER} />
              </tr>
            </thead>
            <tbody>
              {list.map((n) => (
                <tr key={n.id} className="border-t border-grid align-top hover:bg-row-hover">
                  <td className="truncate px-3 py-2 font-mono text-text" title={n.cidr}>{n.cidr}</td>
                  <td className="px-3 py-2 break-words text-text">
                  {n.title || '—'}{n.vlan !== null && <span className="ml-1 text-text-secondary">· VLAN {n.vlan}</span>}
                  {n.origin === 'racktables' && <span className="ml-1 rounded border border-grid px-1 text-[11px] text-text-secondary" title="Создана проходом RackTables: название, описание, VLAN и теги обновляет он; зона и площадка — ваши">RackTables</span>}
                </td>
                  <td className="truncate px-3 py-2 text-text-secondary" title={n.zone ?? undefined}>{n.zone ?? '—'}</td>
                  <td className="truncate px-3 py-2 text-text-secondary" title={n.site || undefined}>{n.site || '—'}</td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums">
                    <Link to={`/assets/list?network_id=${n.id}`} className="text-text hover:underline">{n.assets}</Link>
                  </td>
                  {write && (
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap items-start justify-end gap-1 whitespace-nowrap">
                        <Button variant="ghost" onClick={() => setEditing(n.id)}>изменить</Button>
                        <Button variant="ghost" onClick={() => setDeleting(n)} aria-label={`Удалить сеть ${n.cidr}`}><Trash2 size={13} aria-hidden /></Button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {deleting && <ConfirmDelete network={deleting} onDone={() => setDeleting(null)} />}
    </div>
  )
}
