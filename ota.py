#!/usr/bin/env python3
import sys
import os
import time
import urllib.request
import urllib.error

if len(sys.argv) < 2:
    print("Usage: python3 ota.py <ESP32_IP>")
    print("Example: python3 ota.py 192.168.1.150")
    sys.exit(1)

ESP_IP = sys.argv[1]
BIN_PATH = os.path.join(os.path.dirname(__file__), "build", "esp32_securitychip.bin")

def main():
    if not os.path.exists(BIN_PATH):
        print(f"Error: Binary {BIN_PATH} not found. Run idf.py build first.")
        sys.exit(1)

    bin_size = os.path.getsize(BIN_PATH)
    print(f"[*] Firmware binary: {BIN_PATH} ({bin_size:,} bytes)")
    print(f"[*] Target ESP32 IP: http://{ESP_IP}/update")

    # Read binary
    with open(BIN_PATH, "rb") as f:
        data = f.read()

    password = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("LOCK_PASSWORD", "admin")

    req = urllib.request.Request(
        url=f"http://{ESP_IP}/update",
        data=data,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(data)),
            "X-Auth-Password": password,
        },
        method="POST"
    )

    print("[*] Uploading firmware to ESP32 over Wi-Fi...")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = time.time() - t0
            print(f"[+] Server response ({code}): {body}")
            print(f"[+] Flash complete in {elapsed:.1f}s ({bin_size / elapsed / 1024:.1f} KB/s)")
            print("[*] ESP32 is rebooting into the new firmware...")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Upload failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
