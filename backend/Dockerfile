# Образ API. Ядро анализа и HTTP-слой ставятся одним пакетом,
# но внутри пакета граница сохраняется: kbaudit не знает про базу и HTTP.
FROM python:3.13-slim

# Зависимости ставятся отдельным слоем: их список меняется реже кода,
# и пересборка после правки исходников не тянет сеть заново.
# GHSA updates compare pinned Git trees without downloading the full advisory archive.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY kbaudit ./kbaudit
COPY api ./api
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# pip нужен только здесь, при сборке. В работающем контейнере он лишний,
# а сканеры образов находят уязвимости в копиях пакетов, которые pip
# возит внутри себя (pip/_vendor: msgpack, код setuptools). Поэтому он
# удаляется в том же слое, где отработал, вместе с запасной копией для
# ensurepip; новые зависимости на проде приходят только пересборкой образа.
RUN pip install --no-cache-dir -e ".[api]" \
	&& python -m pip uninstall -y pip \
	&& rm -rf /usr/local/lib/python3.13/ensurepip/_bundled

# Архивы выгрузок и кэш разбора хранятся целиком: без архива нельзя
# перепрогнать старый снапшот доработанным парсером, а без кэша разбора
# не пересчитать снапшот при смене профиля. Каталог монтируется томом,
# иначе всё это живёт в слое контейнера и пропадает при пересоздании.
#
# Непривилегированный пользователь фиксированным uid: том /data переживает
# пересоздание контейнера, и uid должен быть предсказуем, чтобы владение
# не расходилось между пересборками образа.
RUN mkdir -p /data/archives \
	&& groupadd --gid 10001 stools \
	&& useradd --uid 10001 --gid stools --no-create-home --shell /usr/sbin/nologin stools \
	&& chown -R stools:stools /data
ENV STOOLS_DATA_DIR=/data

EXPOSE 8000

# alembic внутри entrypoint только говорит с Postgres по сети — писать
# на диск (кроме /data) ему незачем, поэтому переключаемся до него, а не
# после: raw uvicorn под root между ними в принципе не запускается.
USER stools

# Миграции применяются до старта приложения: иначе сервис поднимается
# с чистыми логами и падает на первом запросе к пустой базе.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Один воркер намеренно: фоновая обработка снапшота живёт в процессе
# приложения, и второй воркер не увидит её заданий.
#
# --forwarded-allow-ips '*': журнал действий пишет адрес клиента, а к API
# приходит только Caddy — без доверия к его X-Forwarded-For в журнале
# стоял бы адрес прокси, один на всех. Звёздочка безопасна потому, что
# порт API не публикуется наружу (ops/docker-compose.yml): достучаться до
# него и подделать заголовок можно только изнутри сети compose.
#
# --no-access-log: в строке запроса /api/auth/oidc/callback приходит код
# авторизации, и доступ-лог сохранял бы его в логах контейнера открытым
# текстом. Запросы и так видит Caddy впереди, а что сделано — журнал действий.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--forwarded-allow-ips", "*", "--no-access-log"]
