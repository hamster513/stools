import type { LlmProvider } from '@/platform/settings/api/types'

export const PROVIDER_NAMES: Record<LlmProvider, string> = {
  ollama: 'Ollama — локально', openrouter: 'OpenRouter', deepseek: 'DeepSeek Platform',
}
