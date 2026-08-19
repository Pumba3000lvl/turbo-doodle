#!/bin/sh
set -e

# Start SSH honeypot
python run_ssh.py &
SSH_PID=$!

# Start HTTP honeypot
python src/honeypot/http_honeypot.py &
HTTP_PID=$!

# Start metrics exporter
python src/honeypot/metrics_exporter.py &
METRICS_PID=$!

# Wait on any process
wait -n $SSH_PID $HTTP_PID $METRICS_PID
EXIT_CODE=$?

# If any process exits, kill the rest and exit
kill $SSH_PID $HTTP_PID $METRICS_PID 2>/dev/null || true
exit $EXIT_CODE
