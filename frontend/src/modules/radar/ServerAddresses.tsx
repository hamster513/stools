import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { dateText } from './api'

interface Binding { addresses: string[]; updated_at: string | null }
function AddressForm({ serverId, binding }: { serverId: number; binding: Binding }) {
  const { write } = useCan('radar')
  const qc = useQueryClient()
  const [value, setValue] = useState(binding.addresses.join('\n'))
  const save = useMutation({ mutationFn: () => api.put<Binding>(`/api/radar/nginx/servers/${serverId}/addresses`, { addresses: value.split(/[\s,;]+/).filter(Boolean) }), onSuccess: () => qc.invalidateQueries({ queryKey: ['radar'] }) })
  return <div className="mt-3 space-y-2 text-sm"><p className="text-text-secondary">Укажите IP интерфейсов этого сервера, если listen содержит только порт. Это ручная привязка для сопоставления с NAT, не проверка доступности. Assets используется автоматически при точном единственном совпадении имени и наличии прав.</p>
    <label className="block space-y-1"><span>IPv4 сервера (по одному на строку)</span><textarea rows={3} className={`${FIELD} w-full`} disabled={!write} value={value} onChange={e => setValue(e.target.value)} /></label>
    {binding.updated_at && <p className="text-xs text-text-secondary">Изменено: {dateText(binding.updated_at)}. Привязка относится к серверу, включая его исторические конфигурации.</p>}
    {write && <><Button loading={save.isPending} onClick={() => save.mutate()}>Сохранить IP</Button><span className="ml-2 text-xs text-text-secondary">Пустое поле удаляет ручную привязку.</span></>}
    {save.error && <p role="alert">{save.error.message}</p>}
  </div>
}
export function ServerAddresses({ serverId }: { serverId: number }) {
  const [open, setOpen] = useState(false)
  const query = useQuery({ queryKey: ['radar', 'addresses', serverId], queryFn: () => api.get<Binding>(`/api/radar/nginx/servers/${serverId}/addresses`), enabled: open })
  return <details className="rounded border border-border p-3" onToggle={e => setOpen(e.currentTarget.open)}><summary className="cursor-pointer text-sm">IP сервера для связи с NetTrace</summary>{open && query.isPending && <p role="status">Загрузка…</p>}{query.error && <p role="alert">{query.error.message}</p>}{query.data && <AddressForm key={query.data.updated_at ?? 'empty'} serverId={serverId} binding={query.data} />}</details>
}
