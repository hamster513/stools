import type { ReactNode } from 'react'

/** Числовое поле: узкое, моноширинное, выровненное по правому краю. */
export const NUM =
  'w-20 rounded border border-border bg-app-bg px-2 py-1 text-right font-mono text-xs ' +
  'tabular-nums text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ' +
  'disabled:cursor-not-allowed disabled:opacity-50'

export const FIELD =
  'w-full rounded border border-border bg-app-bg px-2.5 py-1.5 text-sm text-text ' +
  'placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ' +
  'disabled:cursor-not-allowed disabled:opacity-50'

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-text-secondary">{hint}</span>}
    </label>
  )
}

export function Section({ id, title, about, children }: { id?: string; title: string; about: ReactNode; children: ReactNode }) {
  return (
    <section id={id} className="rounded border border-grid bg-surface p-4">
      <h2 className="mb-1 text-sm font-semibold text-text">{title}</h2>
      <p className="mb-4 max-w-3xl text-xs leading-relaxed text-text-secondary">{about}</p>
      {children}
    </section>
  )
}
