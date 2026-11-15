# Python 3.13 and the base manifest are shared by both target architectures.
ARG PYTHON_IMAGE=python:3.13-alpine3.23@sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2
# Build and sign the SQLite backport against stable Alpine; no edge repositories.
FROM ${PYTHON_IMAGE} AS sqlite-build
RUN apk upgrade --no-cache && apk add --no-cache alpine-sdk readline-dev
COPY docker/sqlite/APKBUILD /build/main/sqlite/APKBUILD
WORKDIR /build/main/sqlite
RUN abuild-keygen -a -n \
    && cp /root/.abuild/*.rsa.pub /etc/apk/keys/ \
    && abuild -F -r \
    && mkdir /out \
    && cp /root/packages/main/*/sqlite-libs-*.apk /out/sqlite-libs.apk \
    && cp /root/.abuild/*.rsa.pub /out/

FROM ${PYTHON_IMAGE} AS build

# Native extension build tools do not enter the runtime image.
RUN apk upgrade --no-cache \
    && apk add --no-cache build-base libffi-dev openssl-dev linux-headers 'expat-dev>=2.10.0'
# Replace bundled Expat in both Python XML extensions, using matching verified sources.
RUN wget -q -O /tmp/python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz" \
    && echo "${PYTHON_SHA256}  /tmp/python.tar.xz" | sha256sum -c - \
    && mkdir /tmp/python-src \
    && tar -xJf /tmp/python.tar.xz -C /tmp/python-src --strip-components=1
WORKDIR /tmp/python-src
RUN ./configure --with-system-expat --enable-shared --with-ensurepip=no \
    && make -j2 "Modules/pyexpat$(python3-config --extension-suffix)" "Modules/_elementtree$(python3-config --extension-suffix)" \
    && cp Modules/pyexpat*.so Modules/_elementtree*.so /usr/local/lib/python3.13/lib-dynload/ \
    && PYTHONPATH=/tmp/python-src/Lib python -m test test_pyexpat test_xml_etree test_xml_etree_c test_minidom test_sax
WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY kbaudit ./kbaudit
COPY api ./api
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -e ".[api]" \
    && /opt/venv/bin/python -m pip uninstall -y pip

FROM ${PYTHON_IMAGE} AS runtime
COPY --from=sqlite-build /out/*.rsa.pub /etc/apk/keys/
COPY --from=sqlite-build /out/sqlite-libs.apk /tmp/sqlite-libs.apk
# Git is required by the GHSA incremental updater; keep HTTPS trust and native libs.
RUN apk upgrade --no-cache \
    && apk add --no-cache git libffi libstdc++ ca-certificates tzdata 'libexpat>=2.10.0' /tmp/sqlite-libs.apk \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip/_bundled /tmp/sqlite-libs.apk
COPY --from=build /usr/local/lib/python3.13/lib-dynload/pyexpat*.so /usr/local/lib/python3.13/lib-dynload/
COPY --from=build /usr/local/lib/python3.13/lib-dynload/_elementtree*.so /usr/local/lib/python3.13/lib-dynload/
COPY --from=build /opt/venv /opt/venv
# Preserve parser error handling on musl worker threads with a bounded native stack.
COPY docker-sitecustomize.py /opt/venv/lib/python3.13/site-packages/sitecustomize.py
COPY --from=build /app /app
COPY --from=build /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV PATH="/opt/venv/bin:$PATH"
# A clean scanner report alone must not hide outdated embedded libraries.
RUN python -c 'import pyexpat,sqlite3; assert pyexpat.version_info >= (2,10,0); assert sqlite3.sqlite_version_info >= (3,54,1)'
WORKDIR /app

# Preserve the existing data-volume ownership across Debian/Alpine deployments.
RUN mkdir -p /data/archives \
    && addgroup -g 10001 stools \
    && adduser -D -H -u 10001 -G stools -s /sbin/nologin stools \
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
