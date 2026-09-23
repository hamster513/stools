/**
 * Хуки TanStack Query модуля ATT&CK. Ключи запросов держим здесь же,
 * чтобы инвалидация не расползалась по компонентам.
 *
 * Снапшота у модуля нет: матрица показывает текущее состояние всех слоёв,
 * а не срез одной выгрузки правил.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import type {
  AttackBundleDiff,
  AttackBundleState,
  AttackChains,
  AttackJob,
  AttackMatrix,
  AttackTechniqueDetail,
  AttackTechniquesResponse,
  PendingBundle,
  RuTtpImportResult,
  RuTtpState,
  TranslateResponse,
  TranslationGapsResponse,
} from './types'

// --- Матрица ----------------------------------------------------------------

/** Матрица целиком, включая незакрытые техники: её смысл в пробелах. */
export function useAttackMatrix() {
  return useQuery<AttackMatrix, ApiRequestError>({
    queryKey: ['attack-matrix'],
    queryFn: () => api.get('/api/attack/matrix'),
  })
}

/** Всё о технике: описание, подтехники, чем закрыта и чем открыта. */
export function useAttackTechniqueDetail(techniqueId: string | undefined) {
  return useQuery<AttackTechniqueDetail, ApiRequestError>({
    queryKey: ['attack-technique', techniqueId],
    queryFn: () => api.get(`/api/attack/technique/${techniqueId}`),
    enabled: techniqueId !== undefined,
  })
}

/** Цепочки реальных кампаний и наши пробелы в них. */
export function useAttackChains() {
  return useQuery<AttackChains, ApiRequestError>({
    queryKey: ['attack-chains'],
    queryFn: () => api.get('/api/attack/chains'),
  })
}

export function useAttackTechniques(q: string) {
  return useQuery<AttackTechniquesResponse, ApiRequestError>({
    queryKey: ['attack-techniques', q],
    queryFn: () => api.get(`/api/attack/techniques${buildQuery({ q })}`),
    enabled: q.trim().length > 0,
  })
}

// --- Обновление матрицы ATT&CK ---------------------------------------------
//
// Матрица общая для всех модулей, и обновляет её администратор в общих
// настройках: ручки живут под /api/settings/attack. Хуки остались здесь —
// состояние матрицы читает и сам модуль (сообщение о замене поставкой).

/** Матрица сменилась — устарело всё, что от неё зависит: поставка
 *  переименовывает техники и пересобирает цепочки. Ключи SIEM живут
 *  в общем QueryClient: его разметка привязана к техникам. */
function invalidateAfterBundleChange(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['attack-bundle'] })
  qc.invalidateQueries({ queryKey: ['attack-matrix'] })
  qc.invalidateQueries({ queryKey: ['attack-technique'] })
  qc.invalidateQueries({ queryKey: ['attack-chains'] })
  qc.invalidateQueries({ queryKey: ['attack-coverage'] })
  qc.invalidateQueries({ queryKey: ['attack-groups'] })
  qc.invalidateQueries({ queryKey: ['rules'] })
  // Загруженный файл делает ожидающую скачанную матрицу устаревшей:
  // её разница посчитана к прежней версии, и карточка «ждёт
  // подтверждения» показывала бы неправду, пока её не перечитают.
  qc.invalidateQueries({ queryKey: ['attack-pending'] })
}

export function useAttackBundle() {
  return useQuery<AttackBundleState, ApiRequestError>({
    queryKey: ['attack-bundle'],
    queryFn: () => api.get('/api/settings/attack'),
  })
}

/** Посмотреть, что приедет, ничего не принимая. */
export function usePreviewBundle() {
  return useMutation<AttackBundleDiff, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/settings/attack/preview', form)
    },
  })
}

export function useUploadBundle() {
  const qc = useQueryClient()
  return useMutation<AttackBundleDiff, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/settings/attack', form)
    },
    onSuccess: () => invalidateAfterBundleChange(qc),
  })
}

/** Человек увидел, что матрицу заменила поставка. */
export function useDismissReplacementNotice() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, void>({
    mutationFn: () => api.post('/api/settings/attack/notice/dismiss'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-bundle'] }),
  })
}

export function useTranslationGaps() {
  return useQuery<TranslationGapsResponse, ApiRequestError>({
    queryKey: ['translation-gaps'],
    queryFn: () => api.get('/api/settings/attack/translation/gaps'),
  })
}

/** Перевод запускает человек: он обращается наружу. */
export function useTranslateBundle() {
  return useMutation<TranslateResponse, ApiRequestError, void>({
    mutationFn: () => api.post('/api/settings/attack/translate'),
  })
}

// --- Загрузка матрицы с сайта MITRE ----------------------------------------

/** Скачивание идёт заданием: файл на полсотни мегабайт не дождаться в
 *  одном запросе. Действующая матрица при этом не меняется. */
export function useDownloadBundle() {
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/settings/attack/download'),
  })
}

/** Скачанное, ждущее подтверждения. null — ничего не ждёт. */
export function usePendingBundle() {
  return useQuery<PendingBundle | null, ApiRequestError>({
    queryKey: ['attack-pending'],
    queryFn: () => api.get('/api/settings/attack/pending'),
  })
}

export function useApplyPendingBundle() {
  const qc = useQueryClient()
  return useMutation<AttackBundleDiff, ApiRequestError, void>({
    mutationFn: () => api.post('/api/settings/attack/pending/apply'),
    onSuccess: () => invalidateAfterBundleChange(qc),
  })
}

/** Отказаться от скачанного, не применяя: матрица не менялась, и
 *  перечитывать её незачем. */
export function useDiscardPendingBundle() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, void>({
    mutationFn: () => api.del('/api/settings/attack/pending'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-pending'] }),
  })
}

// --- Применяемость здесь ----------------------------------------------------

/** Применяемость техник здесь и её расхождение с мировыми данными. */
export function useRuTtpState() {
  return useQuery<RuTtpState, ApiRequestError>({
    queryKey: ['attack-ru-ttp'],
    queryFn: () => api.get('/api/attack/ru-ttp'),
  })
}

/** Загрузка выгрузки. Заменяет прежнюю целиком: выгрузка — один документ
 *  на дату, и слияние двух её версий дало бы картину, которой нет ни
 *  в одной из них. */
export function useUploadRuTtp() {
  const qc = useQueryClient()
  return useMutation<RuTtpImportResult, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/attack/ru-ttp', form)
    },
    onSuccess: () => invalidateRuTtp(qc),
  })
}

export function useDropRuTtp() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, void>({
    mutationFn: () => api.del('/api/attack/ru-ttp'),
    onSuccess: () => invalidateRuTtp(qc),
  })
}

/** Слой виден в матрице, карточке и цепочках — перечитывать надо все три. */
function invalidateRuTtp(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['attack-ru-ttp'] })
  qc.invalidateQueries({ queryKey: ['attack-matrix'] })
  qc.invalidateQueries({ queryKey: ['attack-technique'] })
  qc.invalidateQueries({ queryKey: ['attack-chains'] })
}

// --- Задачи -----------------------------------------------------------------

export function useAttackJobs() {
  return useQuery<AttackJob[], ApiRequestError>({
    queryKey: ['attack-jobs'],
    queryFn: () => api.get('/api/attack/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useAttackJob(jobId: number | undefined) {
  const qc = useQueryClient()
  return useQuery<AttackJob, ApiRequestError>({
    queryKey: ['attack-job', jobId],
    queryFn: async () => {
      const job = await api.get<AttackJob>(`/api/attack/jobs/${jobId}`)
      // Заданием идут и перевод, и загрузка с сайта MITRE. Любое из них
      // кончилось — перечитываем всё, что показывает матрицу: имена
      // техник, карточка, состояние бандла.
      if (job.status !== 'running') {
        qc.invalidateQueries({ queryKey: ['attack-jobs'] })
        qc.invalidateQueries({ queryKey: ['attack-bundle'] })
        qc.invalidateQueries({ queryKey: ['attack-matrix'] })
        qc.invalidateQueries({ queryKey: ['attack-technique'] })
        qc.invalidateQueries({ queryKey: ['translation-gaps'] })
      }
      return job
    },
    enabled: jobId !== undefined,
    refetchInterval: (q) => (q.state.data?.status === 'running' || !q.state.data ? 1000 : false),
    refetchIntervalInBackground: true,
  })
}

// Задания ATT&CK запускает и отменяет администратор — отмена в общих настройках.
export function useCancelAttackJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/settings/attack/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-jobs'] }),
  })
}
