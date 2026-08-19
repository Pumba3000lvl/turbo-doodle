from flask import Flask, request, jsonify
import os
import sqlite3
import time
import logging
from logging.handlers import RotatingFileHandler

# setup rotating log
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LOG_DIR = os.path.join(BASE, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, 'http_honeypot.log')
logger = logging.getLogger('http_honeypot')
if not logger.handlers:
    handler = RotatingFileHandler(log_path, maxBytes=500_000, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'honeypot.db')

app = Flask(__name__)

def log_event(event_type, src_ip, src_port, details=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO events (ts, src_ip, src_port, event_type, command) VALUES (?, ?, ?, ?, ?)',
                (time.strftime('%Y-%m-%d %H:%M:%S'), src_ip, src_port, event_type, details))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def index():
    log_event('http_get', request.remote_addr, request.environ.get('REMOTE_PORT', 0), '/')
    return 'Hello from honeypot', 200

@app.route('/login', methods=['POST'])
def login():
    data = request.form or request.get_json() or {}
    username = data.get('username')
    # Do NOT store plaintext password here
    log_event('http_login', request.remote_addr, request.environ.get('REMOTE_PORT', 0), f'user={username}')
    # Fake response
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload():
    log_event('http_upload', request.remote_addr, request.environ.get('REMOTE_PORT', 0), 'upload')
    return 'uploaded', 200

if __name__ == '__main__':
    host = os.environ.get('HONEYPOT_BIND', '127.0.0.1')
    port = int(os.environ.get('HONEYPOT_HTTP_PORT', '8080'))
    app.run(host=host, port=port)
