/** Session-scoped, memory-only list cache. Auth and job freshness stay unchanged. */
import { CancelledError, MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'
import { ApiRequestError } from './client.ts'

export const LIST_QUERY_OPTIONS = {
  staleTime: 120_000,
  gcTime: 600_000,
  refetchOnWindowFocus: false,
} as const

interface Identity { login: string; auth_source?: string; access: Record<string, string> }
export function sessionKey(me: Identity | null | undefined): string {
  return me ? JSON.stringify([me.login, me.auth_source, Object.entries(me.access).sort(([a], [b]) => a.localeCompare(b))]) : ''
}

type Memory = { owner: string; generation: number; views: Map<string, { value: unknown; at: number }> }
const memories = new WeakMap<QueryClient, Memory>()
const isPrivate = (query: { queryKey: readonly unknown[] }) => !['me', 'oidc-status'].includes(String(query.queryKey[0]))

export function viewOwner(client: QueryClient): string {
  const memory = memories.get(client)
  return memory?.owner ? `${memory.generation}:${memory.owner}` : ''
}

export function readViewState<T>(client: QueryClient, key: string): T | undefined {
  const memory = memories.get(client)
  const entry = memory?.views.get(key)
  if (!entry) return undefined
  if (Date.now() - entry.at > LIST_QUERY_OPTIONS.gcTime) {
    memory?.views.delete(key)
    return undefined
  }
  return entry.value as T
}

export function writeViewState(client: QueryClient, key: string, owner: string, value: unknown): void {
  const memory = memories.get(client)
  // An old page's unmount cleanup must not write into the next user's session.
  if (!memory || !owner || viewOwner(client) !== owner) return
  memory.views.delete(key)
  memory.views.set(key, { value, at: Date.now() })
  // Bound small UI state entries, never truncate infinite-query pages.
  if (memory.views.size > 128) memory.views.delete(memory.views.keys().next().value!)
}

export function createAppQueryClient(): QueryClient {
  const memory: Memory = { owner: '', generation: 0, views: new Map() }
  const mutationOwners = new WeakMap<object, number>()
  let client: QueryClient
  const authError = (error: unknown, query?: { queryKey: readonly unknown[] }) => {
    if (!(error instanceof ApiRequestError)) return
    if (error.status === 401) {
      void client.cancelQueries({ queryKey: ['me'] })
      client.setQueryData(['me'], null)
    }
    else if (error.status === 403 && query?.queryKey[0] !== 'me') {
      // Refresh effective permissions; the failing query remains an error.
      void client.invalidateQueries({ queryKey: ['me'] })
    }
  }
  const queryCache = new QueryCache({ onError: authError })
  client = new QueryClient({
    queryCache,
    mutationCache: new MutationCache({
      onMutate: (_variables, mutation) => { mutationOwners.set(mutation, memory.generation) },
      onSuccess: (_data, _variables, _context, mutation) => {
        // Global callback runs before a hook can write its result into the cache.
        if (mutationOwners.get(mutation) !== memory.generation) throw new CancelledError({ silent: true })
      },
      onError: (error, _variables, _context, mutation) => {
        if (mutationOwners.get(mutation) === memory.generation) authError(error)
      },
    }),
    defaultOptions: { queries: { staleTime: 15_000, retry: 1 } },
  })
  memories.set(client, memory)
  queryCache.subscribe(event => {
    if (event.type !== 'updated' || event.query.queryKey[0] !== 'me' || event.action.type !== 'success') return
    const owner = sessionKey(event.query.state.data as Identity | null)
    if (memory.owner === owner) return
    memory.owner = owner
    memory.generation += 1
    memory.views.clear()
    // Cancel first: an already started response cannot repopulate removed data.
    void client.cancelQueries({ predicate: isPrivate })
    client.removeQueries({ predicate: isPrivate })
    client.getMutationCache().clear()
  })
  return client
}
