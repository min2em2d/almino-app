# ==============================================================================
# Al Mino (al-mino.site) — Apple Virtual Mac Linker & 2FA Cloud Dockerfile
# Multi-Stage Build: Golang 1.22 + Python 3.11 Unicorn Engine + Cloud Vault Sync
# ==============================================================================
FROM golang:1.22-bookworm AS go-builder
WORKDIR /build
COPY go_mac_studio/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /mac_studio_go .

FROM python:3.11-slim-bookworm
WORKDIR /app
RUN pip install --no-cache-dir unicorn cryptography requests urllib3 srp huggingface_hub

COPY --from=go-builder /mac_studio_go /app/mac_studio_go
COPY adi_win_engine.py adi_rpc_worker.py /app/
COPY bin/adid_x86_64 /app/bin/adid_x86_64
COPY mac_auth_system.db* /app/

RUN chmod -R 777 /app
ENV PORT=7860
EXPOSE 7860
CMD ["/app/mac_studio_go", "-port", "7860", "-workers", "4", "-prewarm", "5", "-python", "python3"]
