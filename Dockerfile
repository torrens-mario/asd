# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Create non-root user
RUN useradd -m appuser
WORKDIR /app

# System deps
RUN apt-get update 
RUN apt-get install -y --no-install-recommends curl ca-certificates build-essential 
RUN rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY app ./app
COPY .env.example ./.env.example
COPY scripts ./scripts

# Expose & run
ENV PORT=8000
EXPOSE 8000
USER appuser
CMD [ "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000" ]