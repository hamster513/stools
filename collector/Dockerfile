FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home collector && mkdir /data && chown collector /data
USER collector
VOLUME /data
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,ssl; urllib.request.urlopen('https://127.0.0.1:8443/health/ready', context=ssl._create_unverified_context(), timeout=3)"
ENTRYPOINT ["stools-threat-collector"]
CMD ["serve"]
