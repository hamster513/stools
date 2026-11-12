import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery } from '@/api/client'
import { Link } from '@/lib/router'
import { Button } from '@/components/ui/Button'

type Logon = { id: number; user: string; domain: string; user_id: number | null; table_name: string;
  src_host: string; src_ip: string; dst_host: string; dst_ip: string;
  src_asset_id: number | null; dst_asset_id: number | null; last_login: string }

function Endpoint({ host, ip, id }: { host: string; ip: string; id: number | null }) {
  const title = [host, ip].filter(Boolean).join(' · ') || '—'
  return id ? <Link to={`/assets/list?asset=${id}`} className="text-primary hover:underline">{title}</Link> : <span>{title}</span>
}

export function SiemLogons({ userId, assetId }: { userId?: number; assetId?: number }) {
  const [offset, setOffset] = useState(0)
  const query = useQuery({ queryKey: ['assets', 'siem-logons', userId, assetId, offset],
    queryFn: () => api.get<{ total: number; items: Logon[] }>(`/api/assets/logons${buildQuery({ user_id: userId, asset_id: assetId, offset, limit: 20 })}`) })
  if (query.isPending) return <p className="text-xs text-text-secondary">Загрузка авторизаций SIEM…</p>
  if (query.isError) return <p role="alert" className="text-xs text-risk-high">Не удалось загрузить авторизации SIEM.</p>
  if (!query.data.total) return null
  return <section className="mt-4"><h3 className="mb-2 text-sm font-semibold">Авторизации SIEM ({query.data.total})</h3>
    <p className="mb-2 text-xs text-text-secondary">Последний вход для каждой пары источник → назначение. Это не список активных сеансов.</p>
    <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr>{['Пользователь', 'Откуда', 'Куда', 'Последний вход'].map((s) => <th key={s} className="p-1 text-left">{s}</th>)}</tr></thead><tbody>{query.data.items.map((r) => <tr key={r.id} className="border-t border-grid" title={`Табличный список: ${r.table_name}`}>
      <td className="p-1">{r.user_id ? <Link className="text-primary hover:underline" to={`/assets/users?user=${r.user_id}`}>{r.domain}\{r.user}</Link> : `${r.domain}\\${r.user}`}</td>
      <td className="p-1"><Endpoint host={r.src_host} ip={r.src_ip} id={r.src_asset_id} /></td><td className="p-1"><Endpoint host={r.dst_host} ip={r.dst_ip} id={r.dst_asset_id} /></td>
      <td className="p-1 whitespace-nowrap">{new Date(r.last_login).toLocaleString('ru-RU')}</td>
    </tr>)}</tbody></table></div>
    {query.data.total > 20 && <div className="mt-2 flex gap-2"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Назад</Button><span className="text-xs">{offset + 1}–{Math.min(offset + 20, query.data.total)}</span><Button disabled={offset + 20 >= query.data.total} onClick={() => setOffset(offset + 20)}>Далее</Button></div>}
  </section>
}
