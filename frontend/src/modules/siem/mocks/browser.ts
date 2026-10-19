import { setupWorker } from 'msw/browser'
import { adHandlers } from '@/modules/ad/mocks/handlers'
import { attackHandlers } from '@/modules/attack/mocks/handlers'
import { platformHandlers } from '@/platform/settings/mocks/handlers'
import { huntingHandlers } from '../hunting/mocks/handlers'
import { handlers } from './handlers'

export const worker = setupWorker(...handlers, ...attackHandlers, ...adHandlers, ...platformHandlers, ...huntingHandlers)
