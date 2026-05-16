#!/usr/bin/env python3
"""
Minimal ICAP client for the F99 / RC-IPCam-3X webcam.

Walks through the login1/login2 handshake and prints whatever the camera
sends back. The protocol implementation itself lives in f99_api; this file
is purely the CLI wrapper.

Note: on the device in this repo the ICAP daemon isn't running, so this
script will hit "rst" almost immediately. The handshake is correct against
any other Reecam/Sosocam-family camera whose stream daemon is alive — see
ICAP_PROTOCOL.md.
"""
import argparse
import socket

# Allow `import f99_api` from the parent directory.
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import f99_api as cam_api


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=cam_api.DEFAULT.host)
    ap.add_argument("--port", type=int, default=cam_api.DEFAULT.port)
    ap.add_argument("--user", default=cam_api.DEFAULT.user)
    ap.add_argument("--pwd",  default=cam_api.DEFAULT.pwd)
    args = ap.parse_args()

    s = socket.create_connection((args.host, args.port), timeout=10)
    print(f"[+] connected to {args.host}:{args.port}")

    # Phase 1: send an empty login1_req and see what comes back.
    s.sendall(cam_api.pack_packet(cam_api.TYPE_LOGIN1_REQ, b""))
    print("[>] sent login1_req (empty)")
    try:
        ptype, payload = cam_api.recv_packet(s, timeout=4)
        more = "…" if len(payload) > 64 else ""
        print(f"[<] reply type=0x{ptype:04x} len={len(payload)} hex={payload[:64].hex()}{more}")
        if payload:
            n = payload[0]
            blob_len = ((n + 7) // 8) * 8
            if 1 + blob_len == len(payload):
                bf = cam_api.Blowfish(cam_api.ICAP_DEFAULT_KEY)
                clear = bf.decrypt_ecb(payload[1:])
                print(f"    decrypted (n={n}): {clear[:n]!r}")
                print(f"    full clear:        {clear.hex()}")
    except (socket.timeout, ConnectionError) as e:
        print(f"[!] no login1_resp: {e}")

    # Phase 2: send login2_req.
    pkt = cam_api.build_login2(args.user, args.pwd)
    s.sendall(pkt)
    print(f"[>] sent login2_req user={args.user!r} pwd={args.pwd!r} ({len(pkt)} bytes)")
    try:
        ptype, payload = cam_api.recv_packet(s, timeout=4)
        print(f"[<] reply type=0x{ptype:04x} len={len(payload)} hex={payload.hex()}")
    except (socket.timeout, ConnectionError) as e:
        print(f"[!] no login2_resp: {e}")

    # Phase 3: drain anything else for ~2 s.
    s.settimeout(2)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            more = "…" if len(chunk) > 80 else ""
            print(f"[<] raw {len(chunk)} bytes: {chunk[:80].hex()}{more}")
    except socket.timeout:
        pass
    s.close()


if __name__ == "__main__":
    main()
