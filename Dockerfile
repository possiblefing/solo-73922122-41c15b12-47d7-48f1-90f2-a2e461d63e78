FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY app /srv/app

# 8001/8002 are published individually as well for direct process access;
# nginx on 8080 is the normal browser entrypoint.
EXPOSE 8000

# dumb-init is not needed: uvicorn reaps its own thread pool and we only run
# one process per container.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log"]
