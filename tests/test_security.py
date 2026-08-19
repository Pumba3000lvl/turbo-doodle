import subprocess
import sys
import os

def test_security_check_passes():
    script = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'security_check.py')
    res = subprocess.run([sys.executable, script], capture_output=True, text=True)
    print(res.stdout)
    print(res.stderr)
    assert res.returncode == 0, f"Security check failed: {res.stdout}\n{res.stderr}"
