FROM python:3.12-slim

WORKDIR /app

# Kopioi riippuvuudet ensin (Docker layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopioi sovellus
COPY . .

# Cloud Run kuuntelee PORT-ympäristömuuttujasta (oletus 8080)
ENV PORT=8080

EXPOSE 8080

# Gunicorn: 1 worker riittää Cloud Runille (se skaalaa instansseja)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "60", "main:app"]
