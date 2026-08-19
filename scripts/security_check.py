#!/usr/bin/env python3
"""Basic security checks for honeypot project.
Exits 0 if all checks pass, non-zero otherwise.
"""
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

failed = []

def check_host_key_permissions():
    path = os.path.join(ROOT, 'src', 'honeypot', 'ssh_honeypot.py')
    with open(path, 'r') as f:
        s = f.read()
    if 'write_private_key_file' in s and 'chmod' not in s and 'os.chmod' not in s:
        failed.append('host_key created without os.chmod to restrict permissions')

def check_password_hashing():
    path = os.path.join(ROOT, 'src', 'honeypot', 'ssh_honeypot.py')
    s = open(path,'r').read()
    # accept either hashlib/sha256 or bcrypt
    if not ('sha256' in s or 'hashlib' in s or 'bcrypt' in s):
        failed.append('passwords are not hashed before storage (sha256/hashlib/bcrypt not found)')
    if 'pw_suspicious' not in s:
        failed.append('pw_suspicious flag not set in ssh_honeypot')

def check_metrics_exporter():
    path = os.path.join(ROOT, 'src', 'honeypot', 'metrics_exporter.py')
    s = open(path,'r').read()
    if 'pw_suspicious' not in s:
        failed.append('metrics_exporter does not use pw_suspicious column')
    if 'start_http_server' in s and 'EXPORT_BIND' not in s and 'addr=' not in s:
        failed.append('metrics_exporter starts HTTP server without bind address')

def check_default_bindings():
    # run_ssh.py
    path = os.path.join(ROOT, 'run_ssh.py')
    s = open(path,'r').read()
    if "HONEYPOT_BIND" not in s and "'127.0.0.1'" not in s:
        failed.append('run_ssh.py does not default to 127.0.0.1 or read HONEYPOT_BIND')
    # http honeypot
    path = os.path.join(ROOT, 'src', 'honeypot', 'http_honeypot.py')
    s = open(path,'r').read()
    if "HONEYPOT_BIND" not in s and "'127.0.0.1'" not in s:
        failed.append('http_honeypot.py does not default to 127.0.0.1 or read HONEYPOT_BIND')

if __name__ == '__main__':
    check_host_key_permissions()
    check_password_hashing()
    check_metrics_exporter()
    check_default_bindings()
    if failed:
        print('Security checks failed:')
        for f in failed:
            print('-', f)
        sys.exit(2)
    print('Security checks passed')
    sys.exit(0)
