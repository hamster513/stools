# STools — интерфейс

React 19 + Vite + Tailwind 4. Тема одна, тёмная (`src/index.css`).

```bash
npm ci
npm run dev                        # с MSW-моками, бэкенд не нужен
VITE_USE_MOCKS=false npm run dev   # против настоящего API
npm run build && npm run lint
```

- `src/platform/` — оболочка STools: реестр модулей, рейка, заглушки.
- `src/modules/siem/` — модуль SIEM Rules Analyzer: экраны, API-хуки, моки.
- `src/components/ui/` — общие элементы; всё, что знает про находки и ATT&CK, лежит в модуле.
