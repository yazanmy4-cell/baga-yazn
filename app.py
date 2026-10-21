#!/usr/bin/env python3
"""
run_fix.py
يشغل mitmdump مع fix.py على 0.0.0.0:9999 (بلا Web UI)
الاستخدام:
    python run_fix.py
"""
import subprocess
import sys
import os

# ============ الإعدادات ============
SCRIPT_FILE = "fix.py"
PROXY_HOST = "0.0.0.0"
PROXY_PORT = "9999"
# ===================================

def main():
    if not os.path.exists(SCRIPT_FILE):
        print(f"[ERROR] {SCRIPT_FILE} not found in current directory")
        print(f"        Current dir: {os.getcwd()}")
        sys.exit(1)

    cmd = [
        "mitmdump",
        "-s", SCRIPT_FILE,
        "--listen-host", PROXY_HOST,
        "--listen-port", PROXY_PORT,
        "--set", "block_global=false",   # يسمح باتصالات من أجهزة خارجية
    ]

    print("=" * 60)
    print("Starting mitmdump with fix.py (NO WEB UI)")
    print("=" * 60)
    print(f"Script  : {SCRIPT_FILE}")
    print(f"Proxy   : {PROXY_HOST}:{PROXY_PORT}")
    print("=" * 60)
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("[ERROR] 'mitmdump' not found. Install it with:")
        print("        pip install mitmproxy")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] mitmdump exited with code {e.returncode}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()