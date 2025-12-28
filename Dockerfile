# syntax=docker/dockerfile:1
FROM python:3.12-slim

RUN useradd -m appuser
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY .env.example ./.env.example

RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

ENV PORT=8002
EXPOSE 8002

USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
