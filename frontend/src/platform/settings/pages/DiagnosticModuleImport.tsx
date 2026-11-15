import { ArrowUpRight } from 'lucide-react'
import type { DiagnosticImport } from '../api/diagnostics'
import { DiagnosticSummary } from './DiagnosticSummary'

export function DiagnosticModuleImport({ dataset }: { dataset: DiagnosticImport }) {
  const incomplete = dataset.status === 'incomplete' || dataset.status === 'modified'
  return <section className="space-y-4 rounded border border-grid bg-surface p-4">
    <h2 className="break-words text-lg font-medium">{dataset.root.title}</h2>
    {incomplete ? <p role="alert" className="text-sm text-kind-1">Записи среза изменены или удалены в обычных модулях. Этот импорт больше не является полным воспроизведением исходного пакета.</p> : <>
      <p className="text-sm">Срез загружен в обычные модули. Открывайте объекты, проверяйте связи и настройки политик, запускайте штатный повторный анализ снимков.</p>
      <nav aria-label="Данные среза в обычных модулях" className="flex flex-wrap gap-3">
        {dataset.links?.map(link => <a key={link.href} href={link.href} className="inline-flex min-h-10 items-center gap-2 rounded border border-grid px-3 py-2 text-sm text-primary hover:bg-row-hover">
          {link.module === 'ksc' ? 'AV / KSC' : link.module === 'ad' ? 'AD' : 'Assets'} · {link.title}<ArrowUpRight size={16} aria-hidden />
        </a>)}
      </nav>
    </>}
    <p className="text-sm text-text-secondary">Объекты добавлены к данным стенда. Подключения и задания синхронизации не перенесены. Автоматическое удаление всего среза недоступно: записи могут уже использоваться другими данными модулей.</p>
    <DiagnosticSummary summary={dataset.summary} />
  </section>
}
