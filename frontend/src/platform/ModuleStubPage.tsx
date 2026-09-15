import { ArrowRight } from 'lucide-react'
import { Link } from '@/lib/router'
import type { ModuleSpec } from './modules'

/** Модуль, которого ещё нет: говорит, что он будет делать, и куда идти сейчас. */
export function ModuleStubPage({ module }: { module: ModuleSpec }) {
  const Icon = module.icon
  return (
    <div className="flex h-full items-center justify-center overflow-y-auto p-6">
      <div className="flex max-w-md flex-col items-center gap-3 rounded border border-dashed border-grid px-8 py-12 text-center">
        <Icon size={32} strokeWidth={1.5} className="text-text-secondary" aria-hidden />
        <h1 className="text-base font-semibold text-text">{module.title}</h1>
        <span className="rounded border border-kind-3/50 bg-kind-3/10 px-2 py-0.5 text-[11px] font-medium text-kind-3">
          В разработке
        </span>
        <p className="text-sm text-text-secondary">{module.description}</p>
        <Link
          to="/siem"
          className="mt-2 inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
        >
          Открыть SIEM Rules Analyzer
          <ArrowRight size={14} aria-hidden />
        </Link>
      </div>
    </div>
  )
}
