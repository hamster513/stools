import { useEffect, useRef, useState } from 'react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/platform/collector/ui'
import { TREND_BASE, useTrendMutation, type TrendSource } from '../../../api/trends'
import { useProfiles } from '../../../api/trendMonitoring'
export function SourceEditor({ source, close }: { source: TrendSource; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [form, setForm] = useState(source)
  useEffect(() => { dialog.current?.showModal() }, [])
  const profiles = useProfiles()
  const save = useTrendMutation(async () => {
    const publisher = form.publisher_id || (form.adapter === 'telegram' ? form.url.replace(/^https:\/\/t.me\/(s\/)?/, '').replace(/^@/, '') : new URL(form.url).hostname)
    const payload = { ...form, publisher_id: publisher }
    if (form.id) await api.patch(TREND_BASE + '/sources/' + form.id, payload)
    else await api.post(TREND_BASE + '/sources', payload)
    close()
  })
  return <dialog ref={dialog} aria-labelledby="source-editor-title" onClose={close} onClick={event => {
    if (event.target !== event.currentTarget) return
    const rect = event.currentTarget.getBoundingClientRect()
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) close()
  }} className="fixed inset-0 m-auto max-h-[90dvh] w-[calc(100vw_-_2rem)] max-w-3xl overflow-y-auto rounded-lg border border-grid bg-surface p-5 text-text shadow-xl backdrop:bg-black/40">
    <div className="space-y-3"><h3 id="source-editor-title" className="font-semibold">{source.id ? `Настройка источника: ${source.name}` : 'Новый источник'}</h3>
    <div className="grid gap-3 md:grid-cols-2">
      {(['name', 'url', 'publisher_id', 'language', 'region'] as const).map((key, i) => <Field key={key} label={['Название', 'URL ленты или @канал', 'Издатель (пусто — определить по URL)', 'Язык', 'Регион'][i]}><input className={FIELD} value={form[key]} onChange={e => setForm({ ...form, [key]: e.target.value, ...(key === 'url' ? { telegram_channel: '' } : {}) })} /></Field>)}
      <Field label="Формат"><select className={FIELD} value={form.adapter} onChange={e => setForm({ ...form, adapter: e.target.value, llm_allowed: false })}>{['rss', 'telegram', 'nvd', 'kev', 'msrc', 'github', 'cncert', 'html', 'nvidia'].map(v => <option key={v}>{v}</option>)}</select></Field>
      <Field label="Назначение"><select className={FIELD} value={form.content_scope ?? 'security_news'} onChange={e => setForm({ ...form, content_scope: e.target.value })}>{Object.entries({ security_news: 'Новости ИБ', vendor_advisory: 'Бюллетени', vulnerability_database: 'База уязвимостей', general_it: 'Общие IT-новости', poc_repository: 'PoC' }).map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select></Field>
      <Field label="Интервал, минуты"><input className={FIELD} type="number" min={15} max={10080} value={form.interval_minutes} onChange={e => setForm({ ...form, interval_minutes: +e.target.value })} /></Field>
      <Field label="Приоритет опроса (1–5)"><input className={FIELD} type="number" min={1} max={5} value={form.importance ?? 3} onChange={e => setForm({ ...form, importance: +e.target.value })} /></Field>
      <Field label="Исходящий маршрут сборщика"><select className={FIELD} value={form.proxy_profile ?? 'inherit'} onChange={e => setForm({ ...form, proxy_profile: e.target.value })}>{(profiles.data ?? [{ name: 'inherit', ready: true }]).map(p => <option key={p.name} value={p.name}>{p.name}{p.ready ? '' : ' — недоступен'}</option>)}</select></Field>
      {form.adapter === 'telegram' && <Field label="Доступ к Telegram"><select className={FIELD} value={form.telegram_mode ?? 'web'} onChange={e => setForm({ ...form, telegram_mode: e.target.value })}><option value="web">Публичная веб-версия без входа</option><option value="mtproto">Существующая сессия MTProto</option></select></Field>}
      <Field label="Резервные URL, по одному в строке"><textarea className={FIELD} value={(form.fallback_urls ?? []).join('\n')} onChange={e => setForm({ ...form, fallback_urls: e.target.value.split('\n').filter(Boolean) })} /></Field>
      <label className="flex items-center gap-2"><input type="checkbox" disabled={form.retired} checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />Включить источник</label>
    </div>{form.retired && <p>Источник выведен из эксплуатации. Замена: {form.replacement_key || 'не задана'}</p>}
    <div className="flex gap-2"><Button disabled={save.isPending} onClick={() => save.mutate()}>Сохранить источник</Button><Button onClick={close}>Отмена</Button></div>
    {save.error && <p role="alert">{save.error.message}</p>}
    </div>
  </dialog>
}
