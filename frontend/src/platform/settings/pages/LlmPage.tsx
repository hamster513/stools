import { useEffect, useState } from 'react'
import { CheckCircle2, PlugZap, Save, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useLlm, useLlmModels, useSaveLlm, useTestLlm } from '@/platform/settings/api/queries'
import type { LlmSettings } from '@/platform/settings/api/types'

/**
 * Адрес модели и её параметры. Настройка общая для платформы: один адрес
 * на все модули, а не по копии в каждом — второе место, где то же самое
 * задаётся по-другому, кончается расхождением.
 */
export function LlmPage() {
  const llm = useLlm()
  const save = useSaveLlm()
  const test = useTestLlm()

  const [form, setForm] = useState<LlmSettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)
  const address = form?.base_url.trim().replace(/\/+$/, '') ?? ''
  const [modelsAddress, setModelsAddress] = useState('')
  useEffect(() => {
    const timer = setTimeout(() => setModelsAddress(address), 400)
    return () => clearTimeout(timer)
  }, [address])
  const models = useLlmModels(modelsAddress)
  const matchingAddress = address === modelsAddress
  const names = matchingAddress ? models.data?.models ?? [] : []

  function modelOptions(value: string) {
    const alias = !value.includes(':') && names.includes(value + ':latest')
    return <>
      {!value && <option value="">Выберите модель</option>}
      {value && !names.includes(value) && <option value={value}>
        {value}{alias ? ' (:latest)' : models.isSuccess && matchingAddress ? ' — отсутствует на сервере' : ' — сохранённая'}
      </option>}
      {names.map((name) => <option key={name} value={name}>{name}</option>)}
    </>
  }

  useEffect(() => {
    if (llm.data) setForm(llm.data)
  }, [llm.data])

  if (llm.isError) {
    return (
      <div className="p-6">
        <ErrorState
          message={llm.error?.message ?? 'Не удалось загрузить настройки модели'}
          onRetry={() => llm.refetch()}
        />
      </div>
    )
  }
  if (!form) return <FullPageSpinner />

  function patch(change: Partial<LlmSettings>) {
    test.reset()
    setDirty(true)
    setSaved(false)
    setForm((prev) => (prev ? { ...prev, ...change } : prev))
  }

  function submit() {
    if (!form) return
    save.mutate(form, {
      onSuccess: () => {
        setDirty(false)
        setSaved(true)
      },
    })
  }

  const result = test.data

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Модель LLM</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Модель нужна модулю SIEM для предложений по разметке ATT&CK и переводу техник. Всё
            остальное работает без неё.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saved && !dirty && (
            <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
              <CheckCircle2 size={14} aria-hidden />
              сохранено
            </span>
          )}
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
            <Save size={14} aria-hidden />
            Сохранить
          </Button>
        </div>
      </div>

      {save.isError && <p className="mb-4 text-xs text-kind-1">{save.error.message}</p>}

      <section className="max-w-2xl rounded border border-grid bg-surface p-4">
        <p className="mb-4 text-xs text-text-secondary">
          Пустой адрес — рабочее состояние, а не ошибка: исходящих обращений по умолчанию нет,
          адрес задаёте вы. Наружу уходит только выжимка по группе правил, прошедшая проверку на
          утечку, — тела правил не покидают периметр никогда.
        </p>

        <div className="grid gap-3">
          <Field
            label="Адрес Ollama"
            hint="Например http://ollama:11434. Пусто — предложения по разметке недоступны."
          >
            <input
              className={FIELD}
              value={form.base_url}
              onChange={(e) => patch({ base_url: e.target.value })}
              placeholder="http://хост:11434"
              spellCheck={false}
            />
          </Field>

          <div className="flex flex-wrap items-center gap-3 text-xs">
            <Button variant="ghost" disabled={!address || !matchingAddress} loading={models.isFetching}
              onClick={() => models.refetch()}>Обновить список моделей</Button>
            {(!matchingAddress || models.isFetching) && address && <span role="status">Загрузка моделей…</span>}
            {matchingAddress && models.isError && <span role="alert" className="text-kind-1">{models.error.message}</span>}
            {matchingAddress && models.isSuccess && !names.length && <span>На сервере нет установленных моделей.</span>}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Модель выбора техник" hint="Читает описание правила SIEM и выбирает подходящие техники MITRE ATT&CK из найденных кандидатов. Также переводит описания техник. Выберите языковую модель, например qwen3.5:9b или qwen3:8b-q4_K_M.">
              <select
                className={FIELD}
                value={form.model}
                onChange={(e) => patch({ model: e.target.value })}
                disabled={!matchingAddress || models.isFetching || !names.length}
              >{modelOptions(form.model)}</select>
            </Field>
            <Field label="Модель эмбеддингов" hint="Находит техники, близкие по смыслу к правилу SIEM, и передаёт кандидатов языковой модели. Для этого преобразует тексты в числовые векторы. Выберите модель эмбеддингов, например bge-m3:latest.">
              <select
                className={FIELD}
                value={form.embed_model}
                onChange={(e) => patch({ embed_model: e.target.value })}
                disabled={!matchingAddress || models.isFetching || !names.length}
              >{modelOptions(form.embed_model)}</select>
            </Field>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Таймаут, с">
              <input
                className={FIELD}
                type="number"
                min={5}
                max={1800}
                value={form.timeout}
                onChange={(e) => patch({ timeout: Number(e.target.value) })}
              />
            </Field>
            <div className="flex flex-col justify-end gap-2 pb-1">
              <label className="flex items-center gap-2 text-xs text-text">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => patch({ enabled: e.target.checked })}
                />
                <span>Обращения к модели разрешены</span>
              </label>
              <label className="flex items-center gap-2 text-xs text-text">
                <input
                  type="checkbox"
                  checked={form.think}
                  onChange={(e) => patch({ think: e.target.checked })}
                />
                <span>Режим рассуждения</span>
              </label>
            </div>
          </div>

          <div className="mt-1 flex flex-wrap items-center gap-3 border-t border-grid pt-3">
            <Button
              onClick={() =>
                test.mutate({ base_url: form.base_url, model: form.model, timeout: 90 })
              }
              loading={test.isPending}
              disabled={!form.base_url.trim()}
            >
              <PlugZap size={14} aria-hidden />
              Проверить доступность
            </Button>
            {result && (
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 text-xs',
                  result.ok ? 'text-kind-accepted' : 'text-kind-1',
                )}
              >
                {result.ok ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
                {result.ok ? `модель ответила за ${result.latency_ms} мс` : result.error}
              </span>
            )}
          </div>
          <p className="text-xs text-text-secondary">
            Проверка идёт по адресу из поля выше, а не по сохранённому: проверяется то, что вы
            собираетесь сохранить. Первый ответ после простоя занимает до минуты — модель грузит
            веса в память.
          </p>
        </div>
      </section>
    </div>
  )
}
