FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DORIA_ENV=production \
    DORIA_DB_PATH=/data/doria.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 doria \
    && mkdir -p /data \
    && chown -R doria:doria /app /data

COPY --chown=doria:doria main.py ./main.py
COPY --chown=doria:doria web ./web

USER doria
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
