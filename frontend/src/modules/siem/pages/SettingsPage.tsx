import { useEffect, useState } from 'react'
import { CheckCircle2, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useSettings, useUpdateSettings } from '@/modules/siem/api/queries'
import type { AttackSettings } from '@/modules/siem/api/types'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { useLlm } from '@/platform/settings/api/queries'
import { DataSources } from './settings/DataSources'

export function SettingsPage() {
  const settings = useSettings()
  const update = useUpdateSettings()
  // Модель настраивается в общих настройках; здесь её состояние только
  // показывается: без него непонятно, почему нет предложений по разметке.
  const llm = useLlm()
  const { admin, write } = useCan()

  const [attack, setAttack] = useState<AttackSettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!settings.data) return
    setAttack(settings.data.attack)
  }, [settings.data])

  if (settings.isLoading || !attack) return <FullPageSpinner />
  if (settings.isError) {
    const message =
      settings.error instanceof ApiRequestError
        ? settings.error.message
        : 'Не удалось загрузить настройки'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => settings.refetch()} />
      </div>
    )
  }

  function save() {
    if (!attack) return
    update.mutate(
      { attack },
      {
        onSuccess: () => {
          setDirty(false)
          setSaved(true)
        },
      },
    )
  }

  const configured = Boolean(llm.data?.enabled && llm.data.base_url.trim())

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Настройки</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Разбор выгрузки, поиск хардкода, клоны и критичные списки считаются здесь же и без
            языковой модели — она нужна только для предложений по разметке ATT&CK.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saved && !dirty && (
            <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
              <CheckCircle2 size={14} aria-hidden />
              сохранено
            </span>
          )}
          {write && (
            <Button variant="primary" onClick={save} loading={update.isPending} disabled={!dirty}>
              <Save size={14} aria-hidden />
              Сохранить
            </Button>
          )}
        </div>
      </div>

      {update.isError && (
        <div className="mb-4 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2 text-xs text-text">
          {update.error instanceof ApiRequestError
            ? update.error.message
            : 'Не удалось сохранить настройки'}
        </div>
      )}

      <div className="grid max-w-2xl gap-5">
        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Разметка ATT&CK</h2>
          <p className="mb-4 text-xs text-text-secondary">
            Матрица вложена в образ и не тянется из сети. Подтверждённая разметка привязана к версии
            бандла: между версиями техника может переехать или раздробиться на подтехники.
          </p>

          <div className="grid gap-3">
            <Field
              label="Кандидатов в промпте"
              hint="Отобранные по близости техники, из которых модель выбирает. Замер полноты на эталонной разметке показал плато от 15 до 40 — расширять окно смысла нет."
            >
              {/* Аудитору — значение текстом: менять его он не может, а
                  знать, с каким окном считалась разметка, ему нужно. */}
              {write ? (
                <input
                  className={FIELD}
                  type="number"
                  min={3}
                  max={50}
                  value={attack.top_k}
                  onChange={(e) => {
                    setDirty(true)
                    setSaved(false)
                    setAttack({ ...attack, top_k: Number(e.target.value) })
                  }}
                />
              ) : (
                <span className="block font-mono text-sm text-text">{attack.top_k}</span>
              )}
            </Field>

            <div className="rounded border border-grid px-3 py-2 text-xs text-text-secondary">
              <div className="flex items-center justify-between gap-2">
                <span>Состояние модели</span>
                <span className="flex items-center gap-2">
                  <span className={cn('font-medium', configured ? 'text-kind-accepted' : 'text-kind-3')}>
                    {configured ? 'настроена' : 'не настроена'}
                  </span>
                  {admin && (
                    <Link
                      to="/settings/llm"
                      className="text-primary underline underline-offset-2 hover:text-text"
                    >
                      настроить →
                    </Link>
                  )}
                </span>
              </div>
            </div>

            {!configured && (
              <p className="text-xs text-text-secondary">
                Без модели работают все разделы, кроме предложений по разметке. Разметку можно
                вносить руками — она так и помечается: подтверждено человеком.
                {!admin && ' Адрес модели задаёт администратор в общих настройках.'}
              </p>
            )}
          </div>
        </section>
      </div>

      {/* Все файлы продукта в одном месте: выгрузка правил, матрица,
          эталон и применяемость. Раньше их грузили из четырёх разных
          экранов, и человек вспоминал, какой файл в каком разделе. */}
      <div className="mt-5 max-w-4xl">
        <h2 className="mb-1 text-sm font-semibold text-text">Данные</h2>
        <p className="mb-3 text-xs text-text-secondary">
          Всё, что загружается в продукт. Файлы остаются внутри периметра: они разбираются
          на месте и никуда не отправляются. Разбор загруженного смотрят там, где им
          пользуются, — на экране покрытия ATT&amp;CK.
        </p>
        <div className="flex flex-col gap-4">
          <DataSources />
        </div>
      </div>
    </div>
  )
}
