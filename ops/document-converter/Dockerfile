FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      libreoffice-writer libreoffice-calc libreoffice-impress fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir 'extract-msg==0.55.0' \
    && groupadd -g 10001 stools && useradd -u 10001 -g stools -M stools \
    && mkdir /queue && chown stools:stools /queue
COPY worker.py /app/worker.py
USER 10001:10001
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1
CMD ["python", "/app/worker.py"]
