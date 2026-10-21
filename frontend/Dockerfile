# Сборка интерфейса и раздача статики одним образом.
# Контекст сборки — корень репозитория: образу нужен ещё и ops/Caddyfile.
# Сеть нужна только на этапе сборки; готовый образ наружу не ходит.
FROM node:24-alpine AS build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
# Только по локфайлу: `|| npm install` тихо ставил бы версии мимо
# package-lock.json при рассинхроне, а собранный образ должен быть
# воспроизводим из зафиксированных зависимостей, не из того, что
# резолвится на момент сборки.
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Caddy остаётся от root. Автоматический HTTPS (см. ops/Caddyfile,
# `{$STOOLS_SITE_ADDRESS::80}`: с именем хоста Caddy сам получает сертификат
# и слушает 443) требует бинда портов 80 и 443 — непривилегированному
# пользователю это недоступно без CAP_NET_BIND_SERVICE, а образ caddy:2-alpine
# не содержит готового пользователя (`id caddy` → unknown user, проверено).
# Перенос на порт 8080 внутри снял бы это ограничение, но тогда сломал бы
# автоматический HTTPS по STOOLS_SITE_ADDRESS — то есть ровно то поведение,
# которое эта задача заводит. Раз порт 80 (и с ним root) обязателен для
# заявленного поведения, отдельно решать между непривилегированным
# пользователем и автоматическим HTTPS незачем — оставляем root.
# Бинарник Caddy собирается заново образом-сборщиком: готовый caddy:2-alpine отстаёт
# по версии Go и тащит уязвимости стандартной библиотеки (сканер контейнеров находил
# их в stdlib), а сборщик идёт со свежим Go. Версия Caddy закреплена — та же, что в
# базовом образе, меняется осознанно вместе с ним.
FROM caddy:2-builder-alpine AS caddybuild
ARG CADDY_VERSION=v2.11.7
# Зависимости с известными уязвимостями поднимаются здесь же (--with модуль@версия),
# пока Caddy не выпустит релиз с ними; при смене CADDY_VERSION список пересматривается.
ARG XNET_VERSION=v0.60.0
RUN xcaddy build ${CADDY_VERSION} --with golang.org/x/net/http2@${XNET_VERSION} --output /usr/bin/caddy

FROM caddy:2-alpine
# Пакеты Alpine обновляются при сборке: базовый образ отстаёт от исправлений (zlib).
RUN apk upgrade --no-cache
COPY --from=caddybuild /usr/bin/caddy /usr/bin/caddy
COPY --from=build /app/dist /srv
COPY ops/Caddyfile /etc/caddy/Caddyfile
