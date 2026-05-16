# Next steps — observing the protocol live

> **Most of this file is historical.** The live MJPEG stream now works end-to-end
> via `../icap_stream.py` (~8.6 fps at 1280×720). The remaining gaps below are
> nice-to-have, not blocking. See the "Resolved" list under "What we don't yet
> know" for what's been answered.


`ICAP_PROTOCOL.md` describes what the binary *believes* the protocol is, derived
entirely from static analysis of `librcipcam3x.so`. Several fields are still
labelled `?` because we never watched a real session on the wire. This file
is the playbook to close those gaps.

## What we don't yet know

**Important update from the Moqo-APK session**: the live device speaks the
Moqo generation B of the protocol (magic `0x20130809`, 12-byte header), not
the F99 generation A. **Use the Moqo View APK in the emulator**, not the
F99 APK. Either version 1.1.7 or 1.1.9 is functionally what the iOS app
this camera shipped with was. The 0.1.0.0.4 .so still has its symbol table
so it's the easiest to Ghidra; the others were stripped.

### Resolved

| Was a gap | How it was resolved |
|---|---|
| `login1_req` type / payload | Found in `stream_on_status_changed @ 0x57900` — `add_icap_req(ctx, 0x01F6, NULL, 0)` — type **`0x01F6`**, empty payload. Server replies `0x01FE`. |
| Credentials needed for streaming | **None.** Auth returns `status=1` always; daemon serves the stream anyway. The encrypted user/pwd block in login2_req is cosmetic on this firmware. |
| Whole connect-side wire byte sequence | Verified live (see `../icap_stream.py`): login1_req → login1_resp → login2_req → login2_resp → start_video → loop of (`0x0097` ack + `0x00B0` JPEG frames). |
| 2-byte reserved field at offset 10 | Confirmed ignored by the server when we send `00 00`. Server sometimes returns non-zero bytes there itself; receiver doesn't check them. |
| Video frame format | `0x00B0` packets: 17-byte header + raw JPEG (`FFD8...FFD9`). `frame_size` at offset 13..16 of the header matches `len(payload)-17` exactly. Just slice `payload[17:]`. |

### Still open (not blocking the stream)

| Gap | Why it's nice to know | Where to observe |
|---|---|---|
| Field semantics of bytes 1..12 of the `0x00B0` header | Recover timestamps/frame numbers if needed | Frida hook on `parse_icap_video_data`, or just empirical decoding |
| Status=0 — does any real (user, pwd) yield it? | Curiosity only. Daemon ignores the result on this firmware. | Frida hook + dump `add_icap_login2_req`'s args |
| PTZ command codes | Irrelevant on this unit (`ptz=0`), but useful for other cameras in the family | Frida hook + click PTZ buttons in a real app |
| `start_audio` packet (type `0x00BC`) | Two-way audio. Not yet tried. | Send and listen for `audio_data` packets |

## Setup matrix

| Setup | Time | Answers |
|---|---|---|
| Android Studio AVD + APK only | ~30 min | Sanity check that the app runs (cosmetic) |
| AVD + frida hooks on `librcipcam3x.so` | +30 min | All client-side gaps above |
| AVD + frida + tcpdump on Mac WiFi | +5 min | Same, plus confirms our framing matches what hits the wire |

(Previous "needs a working camera" row removed — we now know the live
camera's daemon does respond, the issue is purely "what to send.")

## Concrete playbook (Apple Silicon, no GUI hand-holding needed)

### One-time setup

```sh
brew install --cask android-platform-tools
brew install --cask android-commandlinetools
brew install pipx
pipx install frida-tools
yes | sdkmanager --install "platform-tools" "platforms;android-30" "system-images;android-30;google_atd;arm64-v8a" "emulator"
echo no | avdmanager create avd -n f99 -k "system-images;android-30;google_atd;arm64-v8a" -d pixel
```

`arm64-v8a` is the key — Apple Silicon runs the ARM image natively, no x86
translator drama, and the APK's `armeabi-v7a` native libs run via Android's
own 32-on-64 thunks.

### Each session

```sh
# 1. boot emulator, headless, with a writable system partition so frida-server
#    can be pushed.  -no-snapshot keeps things deterministic.
emulator -avd f99 -no-snapshot -writable-system &

# 2. wait for boot, push frida-server, run it
adb wait-for-device
adb root
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '/data/local/tmp/frida-server &'

# 3. install the APK
adb install -r F99_1.0.3_APKPure.apk

# 4. make sure the emulator's outbound traffic reaches the camera.
#    The Mac stays on the camera AP, so the AVD's default NAT (10.0.2.0/24
#    → host) already routes packets out via en1 (192.168.1.100).
#    Ping check from inside the emulator:
adb shell ping -c 2 192.168.1.1

# 5. start tcpdump on the Mac side, capturing only camera traffic
sudo tcpdump -i en1 -w f99_session.pcap host 192.168.1.1 &

# 6. launch the app
adb shell monkey -p com.ree.nkj 1

# 7. attach frida with our hook script (write this once and reuse — see below)
frida -U -n com.ree.nkj -l icap_hooks.js
```

### `icap_hooks.js` sketch

```javascript
const lib = Module.findBaseAddress('librcipcam3x.so');
if (!lib) throw new Error('librcipcam3x.so not loaded yet');

function hex(p, n) { return p.readByteArray(n); }

// Builders: dump argument buffer + length before the call is processed.
[
  ['add_icap_req',              (a)=>({type:a[1].toInt32(), buf:a[2], len:a[3].toInt32()})],
  ['add_icap_login2_req',       (a)=>({ctx:a[0]})],
  ['add_icap_ptz_control_req',  (a)=>({ctx:a[0], cmd:a[1].toInt32(), arg:a[2].toInt32()})],
  ['add_icap_speak_data',       (a)=>({ctx:a[0], pkt:a[1]})],
].forEach(([name, fn]) => {
  const sym = Module.getExportByName('librcipcam3x.so', name);
  Interceptor.attach(sym, {
    onEnter(args) {
      const info = fn(args);
      console.log(`>> ${name} ${JSON.stringify(info, (k,v)=> v && v.toString ? v.toString() : v)}`);
    },
  });
});

// Parsers: dump payload bytes when each parse_icap_* runs (= we received
// such a packet, so this reveals S→C type numbers and payload shapes).
[
  'parse_icap_login1_resp', 'parse_icap_login2_resp',
  'parse_icap_video_data',  'parse_icap_video2_data',
  'parse_icap_audio_data',
  'parse_icap_result_class_resp', 'parse_icap_result_str_class_resp',
  'parse_icap_serial_data', 'parse_icap_write_serial_resp',
  'parse_icap_play_record_notify',
].forEach(name => {
  const sym = Module.getExportByName('librcipcam3x.so', name);
  Interceptor.attach(sym, {
    onEnter(args) {
      // most parsers: (ctx, buf, len, ...out_args)
      const len = args[2].toInt32();
      console.log(`<< ${name}  len=${len}  bytes=${hex(args[1], Math.min(len, 96))}`);
    },
  });
});

// Wire-level: hook libc send/recv to compare cleartext vs ciphertext frames.
['send', 'recv'].forEach(name => {
  const sym = Module.getExportByName(null, name);
  Interceptor.attach(sym, {
    onEnter(args) { this.b = args[1]; this.n = args[2].toInt32(); this.name = name; },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0) console.log(`${this.name}=${n} bytes=${hex(this.b, Math.min(n, 96))}`);
    }
  });
});
```

### What to do with the captures

1. **Stop the emulator session once you've clicked through Connect, viewed
   the live screen, used PTZ if available, started/stopped two-way speak.**
   That sequence exercises every interesting C→S packet builder.

2. **Diff the frida log against `ICAP_PROTOCOL.md`.** Things to confirm or
   correct:
   - First packet sent (probably the missing `login1_req` definition).
   - Exact byte ordering inside `login2_req` (we built it from inferred field
     layouts; verify).
   - PTZ `cmd` codes used by the up/down/left/right/zoom buttons.
   - Whether any unexpected helper packet shows up between login2_resp and
     the first video frame (e.g. a separate `start_video` ack).

3. **If by chance the emulator's session reaches a working camera** (e.g.
   you find a different physical unit), the parsers above will fire and
   their bytes settle every server-side gap in one go. Watch the
   `recv()` hex dump for the 10-byte ICAP header — the `type` u16 at
   offset +4 is the S→C type number for whatever parser ran next.

### Where to look for a "working camera" if you want to settle the server side

- Search eBay / AliExpress for the keywords *Reecam* (the original brand),
  *Wingedcam*, *Sosocam*, *HDWIFI 1711*. Lots of these were sold under
  many brands — *MOQO* is just one — and older units typically still have
  the ICAP daemon.
- Search GitHub for the strings `add_icap_login2_req` or the literal
  Blowfish key fragment `hello kitty and kgb/cia` — third-party projects
  that re-implemented the protocol may have committed pcaps as test
  fixtures.
- The Reecam firmware archive (if still online) at `push.reecam.cn` or
  similar; an older `firmware_ver` blob can be reflashed via the
  `set_params.cgi?upgrade_url=…` mechanism that exists on related units
  (not verified here — that param isn't accepted on our build).

## When you do close a gap, update

- `ICAP_PROTOCOL.md` — the spec is the source of truth.
- `../f99_api.py` — keep `pack_packet`/`build_login2` etc. matching reality.
- `../tools/icap_client.py` — exercise whatever's new (e.g. send a real `login1_req`).
- This file — strike completed items off the matrix at the top.
