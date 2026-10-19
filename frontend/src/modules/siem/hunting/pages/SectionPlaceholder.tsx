/** Раздел Threat Hunting, страница которого ещё не готова: маршрут есть, содержимого пока нет. */
export function SectionPlaceholder({ title }: { title: string }) {
  return (
    <div className="p-6">
      <h1 className="mb-2 text-sm font-semibold text-text">{title}</h1>
      <p className="text-xs text-text-secondary">раздел в работе</p>
    </div>
  )
}
