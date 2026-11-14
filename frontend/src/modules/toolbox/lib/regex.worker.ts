import { runRegex, type RegexReply, type RegexRequest } from './regex'

// No user pattern is ever compiled or run on the UI thread.
self.onmessage = (event: MessageEvent<RegexRequest>) => {
  let reply: RegexReply
  try {
    reply = { ok: true, result: runRegex(event.data) }
  } catch (error) {
    reply = { ok: false, error: error instanceof Error ? error.message : 'Ошибка выполнения regex.' }
  }
  self.postMessage(reply)
}
