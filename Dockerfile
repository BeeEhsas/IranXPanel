# IranX Panel — container image
# Build & push once, then any Railway account can deploy it without GitHub:
#   docker build -t youruser/iranx-panel:latest .
#   docker push youruser/iranx-panel:latest

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Railway injects $PORT at runtime
ENV PORT=8080
EXPOSE 8080

CMD gunicorn -k uvicorn.workers.UvicornWorker main:app \
    --bind 0.0.0.0:${PORT} --timeout 0 --workers 1
