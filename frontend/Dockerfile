# Сборка интерфейса и раздача статики одним образом.
# Контекст сборки — корень репозитория: образу нужен ещё и ops/Caddyfile.
# Сеть нужна только на этапе сборки; готовый образ наружу не ходит.
FROM node:24-alpine AS build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install

COPY frontend/ ./
RUN npm run build

FROM caddy:2-alpine
COPY --from=build /app/dist /srv
COPY ops/Caddyfile /etc/caddy/Caddyfile
