import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, errorText } from '@/api/client'
import { useCan } from '@/lib/can'

type Suggestion = {
  summary: string; code: string; original_code: string; generated_at: string; model: string
  changes: { what: string; why: string; impact: string }[]
  dependencies: string[]; tests: { event: string; expected: string }[]; limitations: string[]
  changed_lines: number; lines: { kind: string; a: string | null; b: string | null }[]
}
type Result = { context_hash: string; suggestion: Suggestion | null; stale: boolean }

export function RuleRewrite({ uuid, snapshotId, bodyHash }: { uuid: string; snapshotId: number; bodyHash: string }) {
  const { write } = useCan('siem')
  const client = useQueryClient()
  const key = ['rule-rewrite', snapshotId, uuid, bodyHash]
  const url = `/api/siem/rules/${encodeURIComponent(uuid)}/suggestion?snapshot_id=${snapshotId}`
  const query = useQuery({ queryKey: key, queryFn: () => api.get<Result>(url), retry: false })
  const [tab, setTab] = useState<'explanation' | 'code' | 'diff'>('explanation')
  const [copied, setCopied] = useState('')
  const mutation = useMutation({
    mutationFn: async () => {
      const fresh = await query.refetch()
      if (!fresh.data || fresh.isError) throw fresh.error ?? new Error('Не удалось получить правило')
      return api.post<Result>(url, { context_hash: fresh.data.context_hash })
    },
    onSuccess: (result) => { client.setQueryData(key, result); setCopied('') },
    onError: () => { void client.invalidateQueries({ queryKey: key }) },
  })
  const result = query.data?.suggestion
  const button = 'rounded border border-border px-3 py-1.5 text-xs disabled:opacity-50 hover:bg-bg-hover'
  return <section className="space-y-3 rounded border border-border p-3" aria-label="Исправление правила с ИИ">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-sm font-semibold">Предложение исправления с ИИ</h3>
      {write && <button className={button} disabled={mutation.isPending || query.isFetching || !query.data}
        onClick={() => mutation.mutate()}>{mutation.isPending ? 'Генерация полного правила…' : result ? 'Сгенерировать заново' : 'Предложить исправление с ИИ'}</button>}
    </div>
    <p className="text-xs text-text-secondary">Полный исходник и замечания анализатора обрабатываются локальной Ollama. Модель выбирается в настройках ИИ: «Исправление правил SIEM».</p>
    {query.isLoading && <p role="status" className="text-xs">Загрузка предложения…</p>}
    {query.isError && <div role="alert" className="text-xs text-red-400">{errorText(query.error, 'Не удалось загрузить предложение')} <button className={button} onClick={() => void query.refetch()}>Повторить</button></div>}
    {mutation.isError && <p role="alert" className="text-xs text-red-400">{errorText(mutation.error, 'Не удалось получить предложение')}</p>}
    {query.data?.stale && <p className="text-xs text-amber-400">Исходник или замечания изменились. Предыдущее предложение устарело; создайте новое.</p>}
    {result && <>
      <p className="text-xs text-text-secondary">{result.model} · {new Date(result.generated_at).toLocaleString('ru-RU')} · Изменено строк: {result.changed_lines}</p>
      <p className="text-xs text-amber-400">Предложение ИИ требует проверки аналитиком. Компиляция и проверка на событиях в SIEM не выполнены. Исходное правило не изменено.</p>
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Предложение ИИ">
        {([['explanation', 'Пояснения'], ['code', 'Полный код'], ['diff', 'Что изменилось']] as const).map(([id, name]) =>
          <button key={id} role="tab" aria-selected={tab === id} className={`${button} ${tab === id ? 'bg-bg-hover font-semibold' : ''}`} onClick={() => setTab(id)}>{name}</button>)}
      </div>
      {tab === 'explanation' && <div className="space-y-3 text-xs" role="tabpanel">
        <p className="whitespace-pre-wrap">{result.summary}</p>
        {result.changes.map((change, i) => <div key={i} className="space-y-1 border-l-2 border-border pl-3"><p className="font-semibold whitespace-pre-wrap">{change.what}</p><p className="whitespace-pre-wrap">Причина: {change.why}</p><p className="whitespace-pre-wrap">Влияние: {change.impact}</p></div>)}
        <h4 className="font-semibold">Зависимости и табличные списки</h4>
        {result.dependencies.length ? <ul className="list-disc space-y-1 pl-4">{result.dependencies.map((item, i) => <li key={i} className="whitespace-pre-wrap">{item}</li>)}</ul> : <p>Модель не указала дополнительных изменений зависимостей.</p>}
        <h4 className="font-semibold">Сценарии проверки</h4>
        <ul className="list-disc space-y-2 pl-4">{result.tests.map((test, i) => <li key={i}><p className="whitespace-pre-wrap">{test.event}</p><p className="whitespace-pre-wrap text-text-secondary">Ожидается: {test.expected}</p></li>)}</ul>
        <h4 className="font-semibold">Предположения и ограничения</h4>
        <ul className="list-disc space-y-1 pl-4">{result.limitations.map((item, i) => <li key={i} className="whitespace-pre-wrap">{item}</li>)}</ul>
      </div>}
      {tab === 'code' && <div className="space-y-2" role="tabpanel">
        <button className={button} onClick={async () => {
          try { await navigator.clipboard.writeText(result.code); setCopied('Код скопирован') }
          catch { setCopied('Не удалось скопировать. Выделите код в поле ниже и скопируйте вручную.') }
        }}>Копировать полный код</button><span role="status" className="ml-2 text-xs">{copied}</span>
        <textarea aria-label="Полный исправленный код" readOnly value={result.code} spellCheck={false} className="h-96 w-full resize-y rounded border border-border bg-bg-base p-3 font-mono text-xs" />
      </div>}
      {tab === 'diff' && <div role="tabpanel" className="max-h-[32rem] overflow-auto rounded border border-border">
        <table className="w-full text-left text-xs"><thead><tr><th className="p-2">Исходное правило</th><th className="p-2">Предложение ИИ</th></tr></thead><tbody>
          {result.lines.map((line, i) => <tr key={i}>
            <td className={`border-r border-border align-top ${line.kind === 'delete' || line.kind === 'replace' ? 'bg-red-500/10' : ''}`}><pre className="whitespace-pre-wrap break-all px-2">{line.a == null ? '' : `${line.kind === 'equal' ? ' ' : '−'} ${line.a}`}</pre></td>
            <td className={`align-top ${line.kind === 'insert' || line.kind === 'replace' ? 'bg-green-500/10' : ''}`}><pre className="whitespace-pre-wrap break-all px-2">{line.b == null ? '' : `${line.kind === 'equal' ? ' ' : '+'} ${line.b}`}</pre></td>
          </tr>)}
        </tbody></table>
      </div>}
    </>}
  </section>
}
