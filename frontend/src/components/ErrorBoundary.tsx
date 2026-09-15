import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RotateCcw } from 'lucide-react'

/**
 * Ловушка ошибок отрисовки.
 *
 * Без неё любое расхождение с формой данных с сервера гасит всё
 * приложение: пустой экран без сообщения, без навигации и без выхода —
 * пользователю остаётся только перезагрузить вкладку, не понимая, что
 * произошло. Ошибка обязана оставаться локальной и объяснимой.
 */
interface Props {
  children: ReactNode
  /** Что делать, чтобы вернуться: обычно закрыть панель или уйти на список. */
  onReset?: () => void
  resetLabel?: string
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Подробности — в консоль разработчика, не на экран: текст ошибки
    // может содержать фрагменты данных выгрузки.
    console.error('ошибка отрисовки', error, info.componentStack)
  }

  private handleReset = (): void => {
    this.setState({ error: null })
    this.props.onReset?.()
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <div
        role="alert"
        className="flex h-full min-h-[240px] flex-col items-center justify-center gap-3 p-8 text-center"
      >
        <AlertTriangle className="h-8 w-8 text-severity-2" aria-hidden />
        <div className="text-sm font-medium text-text-primary">
          Не удалось показать этот раздел
        </div>
        <p className="max-w-sm text-xs leading-relaxed text-text-secondary">
          Данные пришли не в том виде, которого ждёт интерфейс. Остальные
          разделы работают — вернитесь и попробуйте ещё раз. Подробности
          ошибки записаны в консоль браузера.
        </p>
        <button
          type="button"
          onClick={this.handleReset}
          className="mt-1 inline-flex items-center gap-2 rounded border border-border-interactive px-3 py-1.5 text-xs text-text-primary transition-opacity duration-150 hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
        >
          <RotateCcw className="h-3.5 w-3.5" aria-hidden />
          {this.props.resetLabel ?? 'Вернуться'}
        </button>
      </div>
    )
  }
}
