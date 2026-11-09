import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Languages, Sparkles } from 'lucide-react'
import { api, buildQuery } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { TREND_BASE, when } from '../../api/trends'
import { safeUrl } from './publicationUrl'

type Mode = 'translate' | 'explain'
interface Answer {
  mode: Mode; translation?: string; summary?: string; danger?: string; affected?: string
  actions?: string[]; limitations?: string[]; provider: string; model: string; generated_at: string
  cached: boolean; stale: boolean; truncated: boolean; sources: { title: string; url: string }[]
}

export function ReadingAssistant({ cardId, publicationKey, revision, originalText, textLabel }: {
  cardId: string; publicationKey?: string; revision?: number; originalText: string; textLabel?: string
}) {
  const { write } = useCan()
  const queryClient = useQueryClient()
  const [showOriginal, setShowOriginal] = useState(false)
  const explanationPanel = useRef<HTMLDetailsElement>(null)
  const target = publicationKey ? { publication_key: publicationKey, revision } : {}
  const url = `${TREND_BASE}/${encodeURIComponent(cardId)}/assistant`
  const queryKey = ['vm-trend-assistant', cardId, publicationKey, revision]
  const saved = useQuery({ queryKey, queryFn: () => api.get<Partial<Record<Mode, Answer | null>>>(url + buildQuery(target)) })
  const request = useMutation({
    mutationFn: (mode: Mode) => api.post<Answer>(url, { mode, ...target }),
    onSuccess: (answer) => {
      queryClient.setQueryData(queryKey, (previous: Partial<Record<Mode, Answer | null>> | undefined) => ({ ...previous, [answer.mode]: answer }))
      if (answer.mode === 'translate') setShowOriginal(false)
    },
  })
  const translation = saved.data?.translate
  const explanation = saved.data?.explain
  const translated = Boolean(translation?.translation && !showOriginal)
  const text = translated ? translation!.translation : originalText
  function translate() {
    request.reset()
    if (translation) setShowOriginal(value => !value)
    else if (write) request.mutate('translate')
  }
  function explain() {
    request.reset()
    if (explanationPanel.current) {
      explanationPanel.current.open = true
      explanationPanel.current.scrollIntoView({ block: 'nearest' })
    } else if (write) request.mutate('explain')
  }
  const textContent = <div className="space-y-2">
    {translated && translation?.stale && <p className="text-xs text-risk-medium">Исходный материал изменился. Показан сохранённый перевод предыдущей версии.</p>}
    <p data-assistant-text className="whitespace-pre-wrap break-words text-xs">{text}</p>
    {translated && <p className="text-[11px] text-text-secondary">Переведено ИИ · {translation!.model} · {when(translation!.generated_at)}{translation!.truncated ? ' · Переведена выдержка из большого материала' : ''}</p>}
  </div>
  return <div className="space-y-2" aria-label={publicationKey ? 'ИИ для публикации' : 'ИИ для CVE'}>
    {(originalText || translation?.translation) && (textLabel
      ? <details key={translation?.generated_at ?? 'original'} open={Boolean(translation)} className="space-y-2"><summary className="cursor-pointer text-xs">{textLabel}</summary>{textContent}</details>
      : textContent)}
    {(write || translation || explanation) && <div className="flex flex-wrap items-center gap-1">
      <Button variant="ghost" className="px-2 py-1 text-xs" disabled={saved.isPending || request.isPending || (!write && !translation)} onClick={translate}><Languages size={14} aria-hidden />{translation ? translated ? 'Показать оригинал' : 'Показать перевод' : 'Перевести'}</Button>
      {translation?.stale && write && <Button variant="ghost" className="px-2 py-1 text-xs" disabled={request.isPending} onClick={() => request.mutate('translate')}>Обновить перевод</Button>}
      <Button variant="ghost" className="px-2 py-1 text-xs" disabled={saved.isPending || request.isPending || (!write && !explanation)} onClick={explain}><Sparkles size={14} aria-hidden />{explanation ? 'К объяснению ИИ' : 'Объяснить'}</Button>
      {saved.isPending && <span role="status" className="text-xs text-text-secondary">Загружаем сохранённые ответы…</span>}
      {request.isPending && <span role="status" className="text-xs text-text-secondary">{request.variables === 'translate' ? 'Переводим…' : 'Готовим объяснение…'}</span>}
    </div>}
    {saved.error && <p role="alert" className="text-xs text-danger">Не удалось загрузить сохранённые ответы: {saved.error.message}</p>}
    {request.error && <p role="alert" className="text-xs text-danger">{request.error.message} <Link to="/settings/llm" className="underline">Настройки ИИ</Link></p>}
    {explanation && <details ref={explanationPanel} key={explanation.generated_at} open className="rounded border border-grid bg-surface p-3 text-xs">
      <summary className="cursor-pointer font-medium">Объяснение ИИ</summary>
      <div className="mt-2 space-y-3">
        {explanation.stale && <div className="space-y-2 text-risk-medium"><p>Исходный материал изменился. Показано сохранённое объяснение предыдущей версии.</p>{write && <Button className="px-2 py-1 text-xs" disabled={request.isPending} onClick={() => request.mutate('explain')}>Обновить объяснение</Button>}</div>}
        <p className="whitespace-pre-wrap break-words">{explanation.summary}</p>
        <div><h5 className="font-medium">Чем опасно</h5><p className="mt-1 whitespace-pre-wrap break-words">{explanation.danger}</p></div>
        <div><h5 className="font-medium">Кого касается</h5><p className="mt-1 whitespace-pre-wrap break-words">{explanation.affected}</p></div>
        {!!explanation.actions?.length && <div><h5 className="font-medium">Что проверить и сделать</h5><ul className="mt-1 list-disc space-y-1 pl-4">{explanation.actions.map((item, i) => <li key={i} className="break-words">{item}</li>)}</ul></div>}
        {!!explanation.limitations?.length && <div><h5 className="font-medium">Что пока неизвестно</h5><ul className="mt-1 list-disc space-y-1 pl-4">{explanation.limitations.map((item, i) => <li key={i} className="break-words">{item}</li>)}</ul></div>}
        {explanation.truncated && <p className="text-text-secondary">Обработаны выдержки: исходный текст превышает объём одного запроса.</p>}
        <p className="text-text-secondary">Сохранено · ИИ · {explanation.model} · {when(explanation.generated_at)}. Сверяйте выводы с источниками; наличие проблемы у нас проверяется отдельно.</p>
        <details className="text-text-secondary"><summary className="cursor-pointer">Использованные материалы ({explanation.sources.length})</summary><ul className="mt-1 space-y-1">{explanation.sources.map((source, i) => <li key={i}>{safeUrl(source.url) ? <a className="underline" href={safeUrl(source.url)} target="_blank" rel="noopener noreferrer">{source.title}</a> : source.title}</li>)}</ul></details>
      </div>
    </details>}
  </div>
}
