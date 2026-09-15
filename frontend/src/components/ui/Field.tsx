import type { ReactNode } from 'react'

/** Класс поля ввода: один на все настройки, иначе формы расходятся по мелочам. */
export const FIELD =
  'w-full rounded border border-border bg-app-bg px-2.5 py-1.5 text-sm text-text ' +
  'placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

export function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: ReactNode
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-text-secondary">{hint}</span>}
    </label>
  )
}
