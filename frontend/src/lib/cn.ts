/** Склеивает классы, отбрасывая ложные значения. Без внешних зависимостей. */
export function cn(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ')
}
