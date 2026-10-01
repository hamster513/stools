# Цель сканера в тестах: слушает TCP 22 и 445, принимает соединение и сразу закрывает,
# ничего не отвечая; на ICMP echo отвечает ядро контейнера.
FROM python:3.13-slim
COPY listen.py /listen.py
CMD ["python", "-u", "/listen.py"]
