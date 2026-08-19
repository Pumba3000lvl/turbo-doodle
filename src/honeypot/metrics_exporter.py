"""Prometheus exporter for honeypot metrics.
Run: python src/honeypot/metrics_exporter.py
Scrapes honeypot.db and exposes /metrics on port 8000
"""
import os
import time
import re
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
from prometheus_client import start_http_server, Gauge

# setup rotating log for exporter
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LOG_DIR = os.path.join(BASE, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, 'metrics_exporter.log')
logger = logging.getLogger('metrics_exporter')
if not logger.handlers:
    handler = RotatingFileHandler(log_path, maxBytes=500_000, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DB_PATH = os.path.join(BASE, 'honeypot.db')
EXPORT_PORT = int(os.environ.get('HONEYPOT_METRICS_PORT', '8000'))
EXPORT_BIND = os.environ.get('HONEYPOT_METRICS_BIND', '127.0.0.1')
POLL_INTERVAL = int(os.environ.get('HONEYPOT_POLL_INTERVAL', '10'))

# heuristics matching dashboard
WEAK_PASSWORDS = {
    '123456', 'password', 'admin', 'qwerty', '1234', '12345', 'letmein', 'root', 'toor'
}

def is_suspicious_password(pw):
    if not pw:
        return False
    s = str(pw)
    if s.lower() in WEAK_PASSWORDS:
        return True
    if len(s) < 6:
        return True
    if re.fullmatch(r'(.)\1{3,}', s):
        return True
    if re.search(r'1234|2345|abcd|qwer', s.lower()):
        return True
    return False

# Prometheus metrics
events_by_type = Gauge('honeypot_events_total', 'Total events by type', ['event_type'])
events_by_ip = Gauge('honeypot_events_by_ip', 'Events by source IP', ['src_ip'])
suspicious_pw_total = Gauge('honeypot_suspicious_passwords_total', 'Count of suspicious passwords')
last_event_ts = Gauge('honeypot_last_event_timestamp', 'Unix timestamp of last event')


def update_metrics():
    if not os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # total by event_type
    cur.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
    rows = cur.fetchall()
    # reset known event types by setting 0 first is not strictly necessary, but we clear common tags by unregistering previous (simple approach: set values to 0 for none)
    for event_type, count in rows:
        events_by_type.labels(event_type or 'unknown').set(int(count))

    # top IPs (limit to 50)
    cur.execute("SELECT src_ip, COUNT(*) as c FROM events GROUP BY src_ip ORDER BY c DESC LIMIT 50")
    rows = cur.fetchall()
    for ip, c in rows:
        events_by_ip.labels(ip or 'unknown').set(int(c))

    # suspicious passwords (use pw_suspicious column set at auth time)
    try:
        cur.execute("SELECT COUNT(*) FROM events WHERE pw_suspicious=1")
        r = cur.fetchone()
        suspicious = int(r[0]) if r and r[0] is not None else 0
    except Exception:
        suspicious = 0
    suspicious_pw_total.set(suspicious)

    # last event timestamp
    cur.execute("SELECT ts FROM events ORDER BY ts DESC LIMIT 1")
    r = cur.fetchone()
    if r and r[0]:
        try:
            # try parse common format
            import datetime
            dt = datetime.datetime.fromisoformat(r[0]) if 'T' in r[0] else datetime.datetime.strptime(r[0], '%Y-%m-%d %H:%M:%S')
            last_event_ts.set(int(dt.timestamp()))
        except Exception:
            try:
                last_event_ts.set(float(time.time()))
            except Exception:
                pass

    conn.close()


def main():
    start_http_server(EXPORT_PORT, addr=EXPORT_BIND)
    logging.info(f'Prometheus metrics available on {EXPORT_BIND}:{EXPORT_PORT}/metrics')
    while True:
        try:
            update_metrics()
        except Exception as e:
            logging.exception('Error updating metrics: %s', e)
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
