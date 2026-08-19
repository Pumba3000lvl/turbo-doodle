Grafana/Prometheus deployment and exporter

1) Import Prometheus-ready Grafana dashboard
- Open Grafana → Dashboards → Import → Upload grafana/prometheus_dashboard.json
- Replace "__PROMETHEUS_DS_UID__" with your Prometheus datasource UID or select the Prometheus datasource during import.

2) Quick start: docker-compose (recommended)
- Ensure docker & docker-compose are installed.
- From project root run:
    docker-compose up -d --build
- Services started:
  - honeypot-app: runs SSH (2222), HTTP (8080) and optionally exporter (8000) inside the same container
  - honeypot-exporter: lightweight exporter container exposing /metrics on 8000
- Metrics: http://localhost:8000/metrics
- Stop: docker-compose down

3) Systemd service (server)
- Copy systemd/honeypot-metrics.service to /etc/systemd/system/honeypot-metrics.service (optional if running exporter as systemd instead of docker)
- Edit file: replace {{REPLACE_WITH_USER}} and {{REPLACE_WITH_PROJECT_PATH}} with appropriate values.
- Reload and enable:
    sudo systemctl daemon-reload
    sudo systemctl enable --now honeypot-metrics
- Logs:
    sudo journalctl -u honeypot-metrics -f

Notes
- docker-compose now builds two images: honeypot-app (full project) and honeypot-exporter (minimal exporter). The exporter can run separately or inside honeypot-app.
- Volumes:
  - honeypot-db: persistent honeypot.db across restarts
  - honeypot-logs: logs folder

- Manual build commands:
    docker build -t honeypot-app -f Dockerfile.app .
    docker build -t honeypot-exporter -f Dockerfile.exporter .

- Run exporter container manually:
    docker run -v $(pwd):/app:ro -v honeypot-db:/app/honeypot.db:ro -p 8000:8000 honeypot-exporter

- If running honeypot-app, ensure ports 2222 and 8080 are available locally.
