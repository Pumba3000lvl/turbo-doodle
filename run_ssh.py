import os
from src.honeypot.ssh_honeypot import start_ssh_honeypot

if __name__ == '__main__':
    bind = os.environ.get('HONEYPOT_BIND', '127.0.0.1')
    port = int(os.environ.get('HONEYPOT_SSH_PORT', '2222'))
    start_ssh_honeypot(listen_addr=bind, port=port)
