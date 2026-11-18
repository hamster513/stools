import { useLayoutEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { readViewState, viewOwner, writeViewState } from '@/api/listCache'

/** Small UI state only. Explicit incoming URL filters take precedence over memory. */
export function useListState<T>(key: string, initial: T | (() => T), restore = true): [T, Dispatch<SetStateAction<T>>] {
  const client = useQueryClient()
  const owner = useRef(viewOwner(client))
  const [value, setValue] = useState<T>(() => {
    const saved = restore ? readViewState<T>(client, key) : undefined
    return saved !== undefined ? saved : typeof initial === 'function' ? (initial as () => T)() : initial
  })
  const latest = useRef(value)
  useLayoutEffect(() => {
    latest.current = value
    writeViewState(client, key, owner.current, value)
  }, [client, key, value])
  useLayoutEffect(() => () => { writeViewState(client, key, owner.current, latest.current) }, [client, key])
  return [value, setValue]
}
