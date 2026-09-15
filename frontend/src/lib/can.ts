import { useMe, type Role } from '@/api/auth'

/**
 * Что можно текущему пользователю. Сервер проверяет права сам; здесь
 * только решается, показывать ли элемент управления: аудитор не должен
 * видеть кнопки, которые для него не работают.
 */
export function useCan(): { role: Role | null; write: boolean; admin: boolean } {
  const { data } = useMe()
  const role = data?.role ?? null
  return { role, write: role === 'admin' || role === 'analyst', admin: role === 'admin' }
}
