FROM python:3.12-slim-bookworm
# nsis      — сборка Windows-установщика (makensis)
# dpkg-dev  — пересборка .deb
# genisoimage — образ .dmg (ISO9660 + Rock Ridge, macOS монтирует его как диск)
ARG HTTP_PROXY
ARG HTTPS_PROXY
RUN apt-get update && apt-get install -y --no-install-recommends nsis dpkg-dev genisoimage ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 ldap3==2.9.1 "psycopg[binary]==3.2.3" psycopg-pool==3.2.4 redis==5.2.1 segno==1.6.1 cryptography==43.0.3
ENV http_proxy="" https_proxy="" HTTP_PROXY="" HTTPS_PROXY=""
WORKDIR /app
COPY app /app
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "21114", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-access-log"]
