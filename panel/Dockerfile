# boris.gb 2026-10-30 00:29 - TrustPanel image: Python + nsenter for restarting the trusttunnel service on the host
FROM python:3.13-alpine

# nsenter (util-linux-misc) — systemctl in the host namespaces; font-dejavu — non-Latin text in the daily report image
# boris.gb 2026-11-01 00:34 - curl: "what is my IP" requests for the Server tab (client path to the internet)
RUN apk add --no-cache util-linux-misc tzdata font-dejavu curl

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests

ENV PYTHONUNBUFFERED=1 \
    PANEL_DATA=/data \
    PANEL_BIND_PORT=8081

# boris.gb 2026-10-30 00:29 - internal port from PANEL_BIND_PORT (8081: 8080 may be taken by awg-panel on the same host)
CMD ["sh", "-c", "exec uvicorn app.main:app --host 127.0.0.1 --port ${PANEL_BIND_PORT} --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-server-header"]
