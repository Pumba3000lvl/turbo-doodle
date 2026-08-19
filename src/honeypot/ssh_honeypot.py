"""Simple SSH honeypot using paramiko.
- Accepts password auth, logs attempts to SQLite, and provides a fake shell that does NOT execute commands.
"""
import os
import socket
import threading
import time
import sqlite3
from paramiko import RSAKey, Transport, ServerInterface
import paramiko
import bcrypt
import logging
import re
from logging.handlers import RotatingFileHandler

# ensure logs dir exists
LOG_DIR = os.path.abspath(os.path.join(BASE, '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, 'honeypot.log')
logger = logging.getLogger('honeypot')
if not logger.handlers:
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# convenience alias to use logger
logging = logger

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DB_PATH = os.path.join(BASE, 'honeypot.db')
HOST_KEY_PATH = os.path.join(BASE, 'host_key.pem')

# Ensure DB exists and has tables
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        src_ip TEXT,
        src_port INTEGER,
        event_type TEXT,
        username TEXT,
        password TEXT,
        command TEXT,
        pw_suspicious INTEGER DEFAULT 0
    )''')
    conn.commit()
    # Ensure pw_suspicious exists for older DBs
    try:
        cur.execute("PRAGMA table_info(events)")
        cols = [r[1] for r in cur.fetchall()]
        if 'pw_suspicious' not in cols:
            cur.execute("ALTER TABLE events ADD COLUMN pw_suspicious INTEGER DEFAULT 0")
            conn.commit()
    except Exception:
        # best-effort; continue
        pass
    conn.close()

# simple suspicious password heuristic
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

class HoneypotServer(ServerInterface):
    def __init__(self, addr):
        self.addr = addr

    def check_auth_password(self, username, password):
        # Hash password before storing and mark suspicious attempts
        try:
            # evaluate suspiciousness before hashing
            pw_susp = 1 if is_suspicious_password(password) else 0
            pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') if password is not None else None
        except Exception:
            pw_hash = None
            pw_susp = 0
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO events (ts, src_ip, src_port, event_type, username, password, pw_suspicious) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (time.strftime('%Y-%m-%d %H:%M:%S'), self.addr[0], self.addr[1], 'auth', username, pw_hash, pw_susp))
        conn.commit()
        conn.close()
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'


def handle_channel(chan, addr):
    chan.send('\r\nWelcome to fake shell\r\n$ ')
    db = sqlite3.connect(DB_PATH)
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break
            cmd = data.decode('utf-8', errors='ignore').strip()
            # Log command
            cur = db.cursor()
            cur.execute('INSERT INTO events (ts, src_ip, src_port, event_type, command) VALUES (?, ?, ?, ?, ?)',
                        (time.strftime('%Y-%m-%d %H:%M:%S'), addr[0], addr[1], 'cmd', cmd))
            db.commit()
            if cmd.lower() in ('exit', 'quit'):
                chan.send('bye\r\n')
                break
            # Echo back
            chan.send(f'Got: {cmd}\r\n$ ')
    finally:
        db.close()
        try:
            chan.close()
        except Exception:
            pass


def start_ssh_honeypot(listen_addr=None, port=2222):
    # default bind: localhost unless overridden by HONEYPOT_BIND env
    if listen_addr is None:
        listen_addr = os.environ.get('HONEYPOT_BIND', '127.0.0.1')
    init_db()
    # Ensure host key
    if not os.path.exists(HOST_KEY_PATH):
        key = RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        try:
            os.chmod(HOST_KEY_PATH, 0o600)
        except Exception:
            pass

    host_key = RSAKey(filename=HOST_KEY_PATH)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, port))
    sock.listen(100)
    logging.info(f"SSH honeypot listening on {listen_addr}:{port}")

    while True:
        client, addr = sock.accept()
        logging.info('Connection from %s', addr)
        try:
            t = Transport(client)
            t.add_server_key(host_key)
            server = HoneypotServer(addr)
            try:
                t.start_server(server=server)
            except Exception as e:
                logging.warning('SSH negotiation failed: %s', e)
                t.close()
                continue
            # Wait for a channel
            chan = t.accept(20)
            if chan is None:
                t.close()
                continue
            # handle channel in thread
            th = threading.Thread(target=handle_channel, args=(chan, addr), daemon=True)
            th.start()
        except Exception as e:
            logging.exception('Error handling connection: %s', e)
            try:
                client.close()
            except Exception:
                pass
