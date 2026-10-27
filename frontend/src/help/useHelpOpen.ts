import { useCallback, useState } from 'react'

const KEY = 'stools-help-open'

function read(): boolean {
  try {
    return sessionStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

function write(open: boolean) {
  try {
    if (open) sessionStorage.setItem(KEY, '1')
    else sessionStorage.removeItem(KEY)
  } catch {
    // Хранилище недоступно (приватное окно, запрет): панель просто не переживёт перезагрузку.
  }
}

/** Открыта ли панель справки; состояние живёт в sessionStorage и переживает переходы между модулями. */
export function useHelpOpen(): { open: boolean; toggle: () => void; close: () => void } {
  const [open, setOpen] = useState(read)

  const toggle = useCallback(() => {
    setOpen((prev) => {
      write(!prev)
      return !prev
    })
  }, [])

  const close = useCallback(() => {
    write(false)
    setOpen(false)
  }, [])

  return { open, toggle, close }
}
