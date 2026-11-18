import { useLayoutEffect, useMemo, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { readViewState, viewOwner, writeViewState } from '@/api/listCache'

export function useListScroll(key?: string) {
  const client = useQueryClient()
  const owner = useRef(viewOwner(client))
  const initialOffset = useMemo(() => key ? readViewState<number>(client, `scroll:${key}`) ?? 0 : 0, [client, key])
  const latest = useRef(initialOffset)
  useLayoutEffect(() => () => {
    if (key) writeViewState(client, `scroll:${key}`, owner.current, latest.current)
  }, [client, key])
  return {
    initialOffset,
    onChange: (instance: { scrollOffset: number | null }) => {
      if (instance.scrollOffset !== null) {
        latest.current = instance.scrollOffset
        if (key) writeViewState(client, `scroll:${key}`, owner.current, instance.scrollOffset)
      }
    },
  }
}
