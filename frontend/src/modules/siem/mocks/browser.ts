import { setupWorker } from 'msw/browser'
import { attackHandlers } from '@/modules/attack/mocks/handlers'
import { platformHandlers } from '@/platform/settings/mocks/handlers'
import { handlers } from './handlers'

export const worker = setupWorker(...handlers, ...attackHandlers, ...platformHandlers)
