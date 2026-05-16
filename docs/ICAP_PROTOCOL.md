# ICAP — Reecam / Sosocam camera wire protocol

Reverse-engineered from `librcipcam3x.so` (the camera SDK inside the F99 Android
app) using Ghidra. Two protocol *generations* exist in the wild, sharing most
of the structure but differing in magic value, header size, and packet type
namespace — see the **"Protocol generations"** section below before going
further. The F99-branded variant in the `com.ree.nkj` Android app uses
generation A (10-byte header, magic `0x118B3305`). The MOQO-branded firmware
on the actual device this repo targets uses generation B (12-byte header,
magic `0x20130809`).

## Protocol generations

Comparing the `librcipcam3x.so` shipped with four different Android SDKs:

| App | Package | Magic | Header | login2 type | login2_resp type | start_video |
|---|---|---|---|---|---|---|
| F99 1.0.3 | `com.ree.nkj` | `0x118B3305` | 10 B | `0x0002` | (not observed) | `0x000E` |
| Moqo View 0.1.0.0.4 | `com.mopoviewer` | `0x20130809` | 12 B | `0x0209` | `0x0215` | `0x0093` |
| Moqo View 1.1.7 | `com.xbcmmoqo` | `0x20130809` | 12 B | `0x0209` | `0x0215` | `0x0093` |
| Moqo View 1.1.9 | `com.xbcmmoqo` | `0x20130809` | 12 B | `0x0209` | `0x0215` | `0x0093` |

`0x20130809` is the date 2013-08-09 packed as four hex digits — almost
certainly the protocol revision date for generation B.

Everything else is the same across both generations: Blowfish-ECB on
credentials, the hardcoded REECAM key, the start/continuation flag pattern
for video frames, the `parse_icap_login1_resp` length-prefix-plus-blob
shape. The Moqo packet type numbers are typically 10× to 50× larger than
F99's, and the relationship between request type and response type appears
to be `resp = req + 0xC` (verified once: `0x0209 + 0xC = 0x0215`).

**On the live F99/MOQO unit at 192.168.1.1**, sending the F99 magic gets
TCP RST; sending the Moqo magic gets a held-open socket; sending a
correctly-framed Moqo `login2_req` gets a real `login2_resp` back. So this
camera speaks **generation B**.

Discovery: generation A uses UDP/10000 with the 5-byte probe
`b4 9a 70 4d 00`. Generation B's discovery probe wasn't grep-able in the
Moqo binary (the same byte sequence is absent) — TBD via deeper RE.

The rest of this document describes the structural shape that is common
to both generations, using generation B's header where the two differ.
Concrete byte offsets/sizes assume the 12-byte header unless explicitly
noted.

## Transport

Plain TCP, same port as the HTTP CGI (default 36299). The library opens a
fresh socket to `(ip, port)` and starts speaking ICAP — no HTTP prologue, no
TLS, no upgrade handshake. The server identifies an ICAP connection by the
4-byte magic at the start of the first packet.

## Packet framing

Every packet, both directions. Generation B (Moqo, the live device here):

```
offset  size  field
0       4     u32 magic = 0x20130809       (wire bytes: 09 08 13 20)
4       2     u16 type                     (little-endian)
6       4     u32 payload_length           (little-endian; header NOT included)
10      2     u16 reserved                 (not written by add_icap_req; rcv'd as 0; semantics unknown)
12      …     payload (payload_length bytes)
```

Generation A (F99/Reecam) is the same minus the 2-byte reserved field, so
the payload starts at offset 10 and the magic is `0x118B3305`.

All multi-byte integers are little-endian. Receiver resynchronises by
scanning for the magic. If fewer than HEADER_LEN bytes are buffered, wait
for more. If fewer than `payload_length + HEADER_LEN` bytes are buffered,
wait. (`parse_icap_data_recved` in either .so does exactly that.)

**On the live F99/MOQO device, when `da_defense=1` (default)**, the daemon
counts failed `login2_req` attempts and locks the *whole port* (both ICAP
and HTTP CGI) for ~160 s after `da_retry_times=10` failures. The lockout
response shape is the same as a normal `login2_resp`, with status byte
still set to the "auth-failed" value and the trailing u32 being the
seconds remaining until unlock. The fastest way out of the lockout is a
power-cycle of the camera. The HTTP-side `set_params.cgi?da_defense=0` is
ignored while the lockout is active.

## Packet types

Two namespaces. Generation A is from the F99/Reecam `librcipcam3x.so`'s
`add_icap_*` callers (`camera_play_video` etc.); generation B is from the
Moqo View 0.1.0.0.4 SDK (which kept the symbol table — 1.1.7/1.1.9 are the
same code but stripped).

| Op | Gen A (F99) | Gen B (Moqo) |
|---|---|---|
| `login1_req` | `0x0001` (presumed) | `0x0109` (presumed) — see open question below |
| `login2_req` | `0x0002` | `0x0209` ← confirmed on the wire |
| `get_properties_req` | `0x0005` | `0x0226` |
| `monitor_status_req` | (not seen) | `0x0076` |
| `start_video` | `0x000E` | `0x0093` |
| `stop_video` | (not seen) | `0x00A4` |
| `play_audio` | (not seen) | `0x00BC` |
| `stop_audio` | (not seen) | `0x00CA` |
| `start_speak` | (not seen) | `0x00E2` |
| `stop_speak` | (not seen) | `0x00F7` |
| `set_video_performance` | (not seen) | `0x011C` |
| `read_serial` | (not seen) | `0x0143` |
| `open_serial` | (not seen) | `0x0159` |
| `close_serial` | (not seen) | `0x016F` |
| `check_timeout` | (not seen) | `0x021E` |
| `get_params_req` | (not seen) | `0x023E` |
| `set_params_req` | (not seen) | `0x024E` |
| `speak_data` | `0x0019` | (TBD) |
| `ptz_control_req` | `0x001A` | (TBD) |
| `write_serial_data` | `0x001E` | (TBD) |
| `play_record_req` | `0x0029` | (TBD) |
| `login2_resp` (S→C) | (not seen) | `0x0215` ← confirmed on the wire (= request + 0xC) |

The response type for any request appears to be `request_type + 0xC` —
confirmed for `0x0209 → 0x0215`. So `0x0093` (start_video) →
`0x009F`, `0x0226` (get_properties) → `0x0232`, etc. The demultiplexer
that routes incoming packets dispatches `parse_icap_*` based on type;
known parsers and their inferred S→C shape:

| Parser | S→C payload shape |
|---|---|
| `parse_icap_login1_resp` | length-prefixed Blowfish blob; cleartext is the camera id echoed back |
| `parse_icap_login2_resp` | 5 bytes: `u8 status, u32 trailing` (status=1 on bad auth; u32 = retries-remaining pre-lockout, or seconds-until-unlock during lockout) |
| `parse_icap_video_data` | legacy frame format, 17-byte header, single packet per frame |
| `parse_icap_video2_data` | fragmented frames with start/continuation flag byte (see below) |
| `parse_icap_audio_data` | 20-byte header + data |
| `parse_icap_play_record_notify` | 8 bytes |
| `parse_icap_result_class_resp` | 1 byte status |
| `parse_icap_result_str_class_resp` | `u8 status, u32 strlen, char data[strlen]` |
| `parse_icap_serial_data` | same shape as `result_str_class_resp` |
| `parse_icap_write_serial_resp` | 5 bytes |

## Login

The transport gateway is the `add_icap_login2_req` packet:

```
login2_req payload:
  +0           u8  user_clear_len            (= strlen(user) + 1, i.e. incl NUL)
  +1           ?   user || NUL || rand_pad   (padded to multiple of 8)
                                              [encrypted with Blowfish-ECB]
  +1+pad8(u)   u8  pwd_clear_len             (incl NUL)
  +2+pad8(u)   ?   pwd  || NUL || rand_pad   (padded to multiple of 8)
                                              [encrypted with Blowfish-ECB]
```

`pad8(n) = ((n + 7) // 8) * 8`. Padding bytes after the trailing NUL are
filled from `lrand48()` after `srand48(get_tick_count() * (i+1))`. Padding
content does not affect authentication; only the cleartext length byte and
the cleartext bytes inside the encrypted block matter.

**Blowfish key**: default is the byte string
`"hello kitty and kgb/cia 2011 COPYRIGHT@REECAM 5460"` (50 bytes, no
trailing NUL). The application can pass a custom key in `create_icap_context`
(arg 4) — `ConnectCameraByIP` always passes NULL, so the hardcoded vendor
string is used.

**Blowfish setup** is the textbook Schneier algorithm; the .so even includes
the standard P-array and S-boxes verbatim. A standard pure-Python Blowfish
implementation interoperates without modification — see `../tools/icap_client.py`.

The matching server response `login1_resp` has the shape:

```
  +0           u8  n
  +1           ?   Blowfish-encrypted blob of pad8(n) bytes
```

After ECB decryption with the same key, the first `n` bytes are returned to
the caller. The blob's *meaning* couldn't be confirmed live, but the call
site keeps it as session-context data (likely the camera's id/serial echoed
back, or a server nonce that's logged but not used in further crypto).

`login2_resp` is just 5 bytes: `u8 status, u32 something` (probably a
session id).

There is no challenge-response: credentials are encrypted with a
static, hardcoded key that's identical on every Reecam-family camera ever
shipped. This means anybody with a packet capture of any login from any
device can offline-brute-force… actually, can just decrypt the credentials
trivially. Security: zero.

## Video framing (`video2_data`)

Frames are split across multiple ICAP packets keyed by a flags byte:

```
  payload[0] = u8 flags
                 bit 0  start_of_frame   (carries a full per-frame header)
                 bit 1  continuation     (just more bytes for the frame body)

When bit 0 is set (first fragment of a new frame):
  payload[1]    u8   ?
  payload[2]    u8   ?       (codec id likely)
  payload[3..5] u8x3 ?       (probably keyframe/seqno fields)
  payload[6..10]  u32 timestamp
  payload[10..14] u32 frame_number
  payload[14..18] u32 total_frame_size
  payload[18..]   first chunk of the codec payload (raw H.264 elementary stream)

When bit 1 is set (continuation):
  payload[1..]    next chunk; append to the accumulator at offset 0x20
```

Receiver allocates `total_frame_size` and appends each chunk's bytes; when
`offset == total_frame_size` the frame is complete. Once complete, the
buffer can be passed straight to an H.264 decoder (`ffplay -f h264 -i -`
style).

There's also a legacy `parse_icap_video_data` that uses a fixed 17-byte
header (no fragmentation flag), single-packet per frame.

## Audio framing (`audio_data`)

20-byte header per packet:

```
  +0       u8   ?
  +1..5    u32  ?            (timestamp?)
  +5..9    u32  ?
  +9..13   u32  ?
  +13..15  u16  ?
  +15      u8   ?
  +16..20  u32  data_size
  +20..    `data_size` bytes of audio payload
```

Codec not yet identified.

## Adjacent UDP services in the SDK

`librcipcam3x.so` opens two UDP sockets in addition to the TCP/ICAP one. Both
are silent on our firmware.

- **UDP/10000 — camera discovery.** `search_cameras` calls
  `p_broadcast_udp_send(socket, ctx, payload, len=5, dport=10000, mode=2)`.
  Payload is the 5 bytes `b4 9a 70 4d 00` (a 4-byte protocol magic +
  1-byte id-filter-length=0 meaning "any camera"). The matching response
  parser is `parse_search_resp`, which reads:
  ```
    u8   id_len;   char  id[id_len];
    u8   alias_len;char  alias[alias_len];
    u8   fw_len;   char  fw_version[fw_len];
    u32  current_ip;  u32 current_mask;
    u8   dhcp;
    u32  gateway; u32 dns1; u32 dns2;
    u32  ip;      u32 mask;
    u16  port;        ← this is what feeds ConnectCameraByIP!
    u8   https;
    u32  id_type      (optional; absent → 0xFFFFFFFF)
    u8   model        (optional)
  ```
  Importantly, the `port` in the discovery response is what gets fed to
  `ConnectCameraByIP`. So the **ICAP port advertised over discovery is not
  necessarily the HTTP/CGI port** — a working camera could in principle put
  its ICAP listener on a port we'd never have probed without discovery.

- **UDP/8081 — audio downlink** (phone-side bind). `audio_udp_thread` binds
  `0.0.0.0:8081` and recv-loops; the camera pushes audio packets there in
  parallel with the TCP/ICAP video.  The Linux htons-coded local port
  (`local_2e = 0x1f91` LE = 0x911F BE = 8081) appears straight in the
  `bind()` setup. Codec format hasn't been confirmed.

## Working live-video flow (generation B)

Verified end-to-end against the live MOQO camera. **Auth `status=1` from
`login2_resp` does NOT actually gate streaming on this firmware** — after
login1 + login2 (regardless of credentials), `start_video` works and the
camera pumps MJPEG frames.

```
Client → Server                          Server → Client
─────────────────────────────────────────────────────────────────────
  pack(0x01F6, b"")                                                    (login1_req, empty)
                                          parse_icap_login1_resp(type=0x01FE, payload=u8 n + pad8(n) bytes Blowfish blob)
  pack(0x0209, login2_payload)                                          (login2_req)
                                          parse_icap_login2_resp(type=0x0215, payload=status(1B) + u32)
                                            status=1 → ignored, stream still flows
  pack(0x0093, b"\x00\x00\x00\x00")                                     (start_video, 4-byte stream handle = 0)
                                          loop:
                                            type=0x0097, payload=1B  (keep-alive / ack)
                                            type=0x00B0, payload=17-byte hdr + JPEG  (video frame)
```

Measured throughput on the live device: **~8.6 fps at 1280×720** with a
single TCP connection, no client-side rate limiting. That's roughly **2×
the snapshot-polling ceiling** and ~3.7× the `resolution=11` snapshot rate.

### `0x00B0` video-frame payload (legacy format, MJPEG)

The 17-byte header in front of each JPEG matches the `parse_icap_video_data`
shape from Ghidra:

```
offset  size  field
0       1     flags (observed: 0x00)
1       1     ?    (observed: 0x0b — sub-stream id maybe)
2       3     ? (sequence?)
5       4     ? (probably timestamp_hi)
9       4     ? (probably timestamp_lo)
13      4     u32 frame_size  (= len(payload) - 17, confirmed)
17      …     raw JPEG bytes (starts with FFD8 SOI; ends with FFD9 EOI)
```

The frame_size in the header matches the JPEG byte count exactly, so a
client can ignore the rest of the header and just slice `payload[17:]`.

`0x0097` ack packets (1-byte payload `0x00`) arrive interleaved with video
frames; appear harmless.

## Resolved questions (vs. what we used to think)

- ~~"`login1_req` payload format is unknown"~~ → Type is **`0x01F6`** (not
  `0x0109` as previously presumed; type `0x01F6` is empty-payload, found
  via `stream_on_status_changed @ 0x00057900` which calls
  `add_icap_req(ctx, 0x1F6, NULL, 0)` right after TCP connect).
- ~~"status=1 means bad creds"~~ → Almost. The daemon DOES validate
  user/pwd and DOES record retries in the u32 trailer of `login2_resp`,
  but **the validation result doesn't actually gate `start_video`** on
  this firmware. The MOQO View app probably reports auth success or
  failure but proceeds either way. Practical implication: **you can stream
  without knowing the password**.
- ~~"2-byte reserved at offset 10 might matter"~~ → It doesn't matter on
  the client→server side; zeros work. The server fills these bytes with
  non-zero content sometimes (`0x6172` = "ra" was observed), but those are
  not checked by the receiver.

## Still-open questions

- The 17-byte `0x00B0` video header has 13 bytes labelled `?`. Timestamps
  are recoverable empirically, but the exact field semantics aren't.
- Auth that actually returns `status=0` — does any (user, pwd) yield it?
  We brute-forced 40 common defaults + a few-hundred 4-digit PINs (then
  bailed because the stream works without). Curiosity only.
- `0x0097` ack packets — do we need to send something in return? Empirically
  the stream keeps flowing without us answering, so probably not.
- Audio (`audio_data`) — `start_audio` is `0x00BC`. Untested.
- PTZ — irrelevant on this unit (`ptz=0`).

## Why this didn't run on our device

After implementing the protocol per spec, every ICAP packet sent to
`192.168.1.1:36299` is met with an immediate TCP RST — including the bare
magic alone. HTTP requests on the same port and same connection succeed
normally (`GET /…cgi` returns the documented JSON; `OPTIONS`, `DESCRIBE`,
non-`GET` methods all RST). nmap finds **no other open TCP port**. UDP/10000
(discovery) and UDP/8081 (audio) are both silent. The CGI
`set_params.cgi?sosocam=1` returns `{"error":-2}` (rejected — the field is
read-only). We probed 40+ candidate `set_params` toggles, every known
`reinit_*` variant, every plausible "wakeup" CGI name, and the broader
firmware accepts only `reinit_video / reinit_record / reinit_network /
reinit_user / reinit_http / reinit_camera` — notably no `reinit_stream`
and no `reinit_audio`, consistent with those subsystems not existing as
services on this build.

A keyword sweep of the dex turned up two new CGI tricks we'd missed
(`snapshot.cgi?streamid=N` and `set_params.cgi?reinit_camera=1`) but
neither brings up the listener. There are zero hidden `*.cgi` paths in
either the dex or the .so beyond the 13 already documented.

The architectural reason no CGI hack could work: the SDK starts live video
by sending a binary ICAP packet (type `0x000e`) over the already-open
TCP/36299 connection — see `camera_play_video` in the .so. There's no HTTP
"begin streaming" call anywhere in the SDK. CGI is purely a sideband.

Conclusion: on this firmware build (`firmware_ver=0.1.00000101.3.33`,
`sosocam=0`, alias prefix `MOQO-`) **the camera-side daemon that would own
TCP/36299 ICAP + UDP/10000 discovery + UDP/8081 audio simply isn't bound to
any of those sockets**, even though the Android SDK is fully equipped to
talk to it. The single most plausible explanation remains "this firmware
build was stripped or its daemon broke"; the only definitive way to settle
it without taking the camera apart is a packet capture of the original app
talking to a working camera.

The protocol notes above are nonetheless directly usable against any
Reecam/Sosocam/Wingedcam camera that still has the live stream service
running, which covers a large fraction of cheap Chinese IP cams sold under
brand names like Reecam, MOQO, HDWIFI, EsiCam, Wingedcam, etc.
