import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'

/**
 * Виртуальный список строк одной высоты: держит выбранную строку в поле
 * зрения и зовёт onReachEnd, когда до конца загруженного осталось 20 строк.
 */
export function useVirtualRows(count: number, rowHeight: number, selectedIndex: number, onReachEnd?: () => void) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count, getScrollElement: () => parentRef.current, estimateSize: () => rowHeight, overscan: 12 })
  useEffect(() => {
    if (selectedIndex >= 0 && selectedIndex < count) virtualizer.scrollToIndex(selectedIndex, { align: 'auto' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex])
  const rows = virtualizer.getVirtualItems()
  const last = rows.length ? rows[rows.length - 1].index : 0
  useEffect(() => {
    if (onReachEnd && count > 0 && last >= count - 20) onReachEnd()
  }, [last, count, onReachEnd])
  return { parentRef, rows, totalSize: virtualizer.getTotalSize() }
}
