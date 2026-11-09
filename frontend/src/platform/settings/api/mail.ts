import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'

export interface MailConfig {
  enabled: boolean
  host: string
  port: number
  security: 'starttls' | 'tls' | 'none'
  from_address: string
  from_name: string
  auth_enabled: boolean
  username: string
  timeout: number
}
export interface MailSettings extends MailConfig { has_password: boolean }
export interface MailInput extends MailConfig { password?: string | null }
export interface MailResult { accepted: boolean; message_id: string }

export function useMail() {
  return useQuery<MailSettings, ApiRequestError>({
    queryKey: ['settings-mail'], queryFn: () => api.get('/api/settings/mail'),
  })
}
export function useSaveMail() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, MailInput>({
    mutationFn: (body) => api.put('/api/settings/mail', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings-mail'] }),
  })
}
export function useTestMail() {
  return useMutation<MailResult, ApiRequestError, { settings: MailInput; recipient: string }>({
    mutationFn: (body) => api.post('/api/settings/mail/test', body),
  })
}
