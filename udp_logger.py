import socket
import datetime
import sys

PORT = 8888
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except Exception:
    pass

sock.bind(("0.0.0.0", PORT))
print(f"[{datetime.datetime.now()}] UDP Logger listening on 0.0.0.0:{PORT}...")
sys.stdout.flush()

import os
log_file = os.path.join(os.path.dirname(__file__), "net_log.txt")
with open(log_file, "a", encoding="utf-8") as f:
    f.write(f"=== Session started at {datetime.datetime.now()} ===\n")
    f.flush()
    while True:
        data, addr = sock.recvfrom(4096)
        text = data.decode("utf-8", errors="replace")
        line = f"[{addr[0]}] {text}"
        sys.stdout.write(line)
        sys.stdout.flush()
        f.write(line)
        f.flush()
