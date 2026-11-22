# Container image for the single-file panel.
# Build and push once, then any Railway account can deploy it without a repo:
#   docker build -t youruser/webapp:latest .
#   docker push youruser/webapp:latest

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# The hosting platform injects $PORT at runtime
ENV PORT=8080
EXPOSE 8080

CMD gunicorn -k uvicorn.workers.UvicornWorker main:app \
    --bind 0.0.0.0:${PORT} --timeout 0 --workers 1
