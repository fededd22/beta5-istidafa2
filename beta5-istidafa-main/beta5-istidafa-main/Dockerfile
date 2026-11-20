
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY beta5-istidafa-main/beta5-istidafa-main/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY beta5-istidafa-main/beta5-istidafa-main/istidafa4_by_moon.py ./
COPY beta5-istidafa-main/beta5-istidafa-main/keepalive.py ./
COPY beta5-istidafa-main/beta5-istidafa-main/botconfig.py ./
COPY beta5-istidafa-main/beta5-istidafa-main/serverinfo.py ./
COPY beta5-istidafa-main/beta5-istidafa-main/countries_ar.py ./
COPY beta5-istidafa-main/beta5-istidafa-main/.env.example ./.env.example
COPY beta5-istidafa-main/beta5-istidafa-main/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN groupadd -g 10014 appuser \
    && useradd -u 10014 -g appuser -m -s /bin/sh appuser \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chown -R 10014:10014 /app \
    && chown 10014:10014 /usr/local/bin/docker-entrypoint.sh

EXPOSE 3000 8080

USER 10014

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["python", "istidafa4_by_moon.py"]
