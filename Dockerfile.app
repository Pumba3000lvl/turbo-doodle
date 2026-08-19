# Dockerfile for full honeypot project (SSH + HTTP + exporter)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN addgroup --system honeypot && adduser --system --ingroup honeypot honeypot

WORKDIR /app

# Install build deps required for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev libffi-dev build-essential libsqlite3-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . /app

# Install full requirements
RUN pip install --no-cache-dir -r requirements.txt

# Expose ports for SSH and HTTP (and metrics if running in same container)
EXPOSE 2222 8080 8000

# Use non-root user
USER honeypot

# Ensure start script is executable
ENTRYPOINT ["/app/start_services.sh"]
