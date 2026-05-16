#!/usr/bin/env python3
"""
Pseudo-live-stream for the F99 / HD WiFi 1711-2 webcam.

Polls /snapshot.cgi over a kept-alive HTTP connection and exposes the
result as an MJPEG stream on http://127.0.0.1:8080/ that VLC, ffmpeg,
or any browser can consume directly.

Practical ceiling on this firmware is ~4 fps at 1280x720; the camera's
JPEG encoder, not the network, is the bottleneck. See f99_api.py and
README.md for the encoder-wedge warning.
"""
import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Allow `import f99_api` from the parent directory.
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import f99_api as cam_api

# Two ways to ask for a frame (see f99_api.snapshot_path docstring):
#   USE_STREAMID=True  → snapshot.cgi?streamid=N (lower overhead, ~80% faster)
#   USE_STREAMID=False → snapshot.cgi?resolution=N (also persists RESOLUTION)
USE_STREAMID = True
STREAM       = 0
RESOLUTION   = cam_api.RES_1280x720

POLL_INTERVAL    = cam_api.SAFE_POLL_INTERVAL   # ~2.5 fps target — keep below the wedge threshold
BACKOFF_INTERVAL = 5.0

LISTEN   = ("127.0.0.1", 8080)
BOUNDARY = "f99frame"


_latest_frame = None
_latest_lock = threading.Condition()


def poller():
    global _latest_frame
    snapshot_kwargs = ({"streamid": STREAM} if USE_STREAMID else {"resolution": RESOLUTION})
    failures_in_a_row = 0
    while True:
        try:
            conn = http.client.HTTPConnection(
                cam_api.DEFAULT.host, cam_api.DEFAULT.port, timeout=10
            )
            while True:
                t0 = time.monotonic()
                data = cam_api.fetch_snapshot(conn=conn, **snapshot_kwargs)
                with _latest_lock:
                    _latest_frame = data
                    _latest_lock.notify_all()
                failures_in_a_row = 0
                dt = time.monotonic() - t0
                if dt < POLL_INTERVAL:
                    time.sleep(POLL_INTERVAL - dt)
        except (OSError, http.client.HTTPException, RuntimeError) as e:
            failures_in_a_row += 1
            if failures_in_a_row == 1:
                print(f"[poller] {e}; backing off to {BACKOFF_INTERVAL}s")
            elif failures_in_a_row % 20 == 0:
                print(f"[poller] still failing ({failures_in_a_row}x): {e}; "
                      f"if this persists for minutes, power-cycle the camera")
            time.sleep(BACKOFF_INTERVAL)


class MJPEGHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence stock access log

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
            self.send_header(
                "Content-Type", f"multipart/x-mixed-replace; boundary={BOUNDARY}"
            )
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
    threading.Thread(target=poller, daemon=True).start()
    print(f"Pseudo-stream on http://{LISTEN[0]}:{LISTEN[1]}/  (MJPEG at /stream, JPEG at /snapshot.jpg)")
    ThreadingHTTPServer(LISTEN, MJPEGHandler).serve_forever()
