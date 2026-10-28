# VAULT - laboratorio vulneravel (INFOESTE 2026)
FROM python:3.12-slim
WORKDIR /app
COPY app/ ./app/
ENV VAULT_BIND=0.0.0.0 VAULT_PORT=8099 VAULT_DB=/data/vault.db VAULT_SECURITY_MODE=vulnerable
RUN mkdir -p /data && chmod 777 /data
USER 65534
EXPOSE 8099
HEALTHCHECK --interval=10s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8099/api/health')" || exit 1
CMD ["python", "-m", "app.server"]
