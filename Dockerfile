FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

# non-root user
RUN useradd -m appuser
WORKDIR /app

ARG HTTP_PORT=3000
ARG SOCKET_PORT=5000

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/

EXPOSE ${HTTP_PORT} ${SOCKET_PORT}

USER appuser

CMD ["python", "main.py"]
