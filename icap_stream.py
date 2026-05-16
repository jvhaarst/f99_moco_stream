#!/usr/bin/env python3
"""
Live MJPEG bridge using the ICAP binary protocol (generation B / Moqo).

Connects to the camera's TCP/36299, does the (cosmetic) login1/login2 dance,
sends start_video (type 0x0093), then re-publishes every 0x00B0 video packet
as JPEG on http://127.0.0.1:8081/ (HTML page + `/stream` MJPEG + `/snapshot.jpg`).

Measured on the live MOQO firmware: ~8.6 fps at 1280×720, ~2× the snapshot
polling rate. No rate limit needed — the camera pushes frames at its
encoder speed without our prompting.

The auth always returns status=1 on this firmware, but the daemon serves
the stream anyway. See ICAP_PROTOCOL.md.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import f99_api as cam

MOQO_MAGIC = 0x20130809
MAGIC_BYTES = struct.pack("<I", MOQO_MAGIC)

TYPE_LOGIN1_REQ_B  = 0x01F6
TYPE_LOGIN2_REQ_B  = 0x0209
TYPE_START_VIDEO_B = 0x0093
TYPE_VIDEO_FRAME_B = 0x00B0
TYPE_KEEPALIVE_B   = 0x0097
TYPE_LOGIN1_RESP_B = 0x01FE
TYPE_LOGIN2_RESP_B = 0x0215

LISTEN   = ("127.0.0.1", 8081)
BOUNDARY = "f99frame"

_latest_frame: bytes | None = None
_latest_lock = threading.Condition()


def pack_moqo(ptype: int, payload: bytes = b"") -> bytes:
    """12-byte-header Moqo packet (gen B)."""
    return struct.pack("<IHI", MOQO_MAGIC, ptype, len(payload)) + b"\x00\x00" + payload


def build_login2(user: str, pwd: str, key: bytes = cam.ICAP_DEFAULT_KEY) -> bytes:
    bf = cam.Blowfish(key)
    u = user.encode() + b"\x00"
    p = pwd.encode() + b"\x00"

    def block(s: bytes) -> tuple[bytes, int]:
        padded = s + os.urandom((-len(s)) % 8)
        return bf.encrypt_ecb(padded), len(s)

    u_enc, u_len = block(u)
    p_enc, p_len = block(p)
    return pack_moqo(TYPE_LOGIN2_REQ_B,
                     bytes([u_len]) + u_enc + bytes([p_len]) + p_enc)


def iter_packets(sock: socket.socket):
    """Yield (type, payload) tuples forever, consuming from sock."""
    buf = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("camera closed connection")
        buf.extend(chunk)
        while True:
            i = buf.find(MAGIC_BYTES)
            if i < 0:
                break
            if len(buf) - i < 12:
                break
            _, ptype, plen = struct.unpack_from("<IHI", buf, i)
            if len(buf) - i < 12 + plen:
                break
            payload = bytes(buf[i + 12:i + 12 + plen])
            del buf[:i + 12 + plen]
            yield ptype, payload


def streamer():
    global _latest_frame
    while True:
        try:
            s = socket.create_connection((cam.DEFAULT.host, cam.DEFAULT.port), timeout=10)
            s.sendall(pack_moqo(TYPE_LOGIN1_REQ_B))
            s.sendall(build_login2(cam.DEFAULT.user, cam.DEFAULT.pwd))
            s.sendall(pack_moqo(TYPE_START_VIDEO_B, b"\x00\x00\x00\x00"))
            print("[icap] handshake sent; reading frames")
            for ptype, payload in iter_packets(s):
                if ptype == TYPE_VIDEO_FRAME_B and len(payload) >= 17:
                    jpg = payload[17:]
                    if jpg.startswith(b"\xff\xd8"):
                        with _latest_lock:
                            _latest_frame = jpg
                            _latest_lock.notify_all()
                # silently consume keep-alives and login-resp packets
        except (OSError, ConnectionError) as e:
            print(f"[icap] {e}; reconnecting in 2s")
            time.sleep(2)


class MJPEGHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='margin:0;background:#000'>"
                b"<img src='/stream' style='max-width:100vw;max-height:100vh'/>"
                b"</body></html>"
            )
            return
        if self.path == "/snapshot.jpg":
            with _latest_lock:
                _latest_lock.wait_for(lambda: _latest_frame is not None, timeout=5)
                frame = _latest_frame
            if frame is None:
                self.send_error(503, "no frame yet")
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(frame)))
            self.end_headers()
            self.wfile.write(frame)
            return
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", f"multipart/x-mixed-replace; boundary={BOUNDARY}")
            self.end_headers()
            last = None
            try:
                while True:
                    with _latest_lock:
                        _latest_lock.wait_for(
                            lambda: _latest_frame is not None and _latest_frame is not last,
                            timeout=5,
                        )
                        frame = _latest_frame
                    if frame is None or frame is last:
                        continue
                    last = frame
                    head = (
                        f"--{BOUNDARY}\r\n"
                        f"Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(frame)}\r\n\r\n"
                    ).encode()
                    self.wfile.write(head)
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                return
        self.send_error(404)


if __name__ == "__main__":
    threading.Thread(target=streamer, daemon=True).start()
    print(f"ICAP live stream on http://{LISTEN[0]}:{LISTEN[1]}/  (MJPEG at /stream, JPEG at /snapshot.jpg)")
    ThreadingHTTPServer(LISTEN, MJPEGHandler).serve_forever()
