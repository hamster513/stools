import { Link } from '@/lib/router'

/** Заглушка страницы образа: её заменяет задача 8 (карточка образа с уязвимостями). */
export function ImagePage({ id }: { id: number }) {
  return (
    <div className="p-6 text-sm text-text-secondary">
      <Link to="/vm/images" className="text-primary underline underline-offset-2 hover:text-text">Образы контейнеров</Link>
      <span className="mx-1.5">›</span>
      <span className="font-mono text-text">образ #{id}</span>
    </div>
  )
}
