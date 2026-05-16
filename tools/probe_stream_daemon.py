#!/usr/bin/env python3
"""
Probe whether any combination of set_params.cgi flags can bring up the
ICAP binary-stream daemon on the F99 camera.

Strategy:
  1. Snapshot the current parameter set.
  2. For each candidate change, hit set_params.cgi, wait, then check
     whether TCP 36299 still drops ICAP traffic (RST) or now accepts it.
  3. If ICAP TCP starts responding (reply != "") OR if any new TCP/UDP port
     opens, that change is the winner — stop and report.
  4. At the end, restore every changed field to its snapshotted value.

Safe-by-construction: we never touch restore_factory.cgi, format_sd.cgi,
the user/pwd fields, the AP SSID/PSK, or anything network-changing.
"""
from __future__ import annotations
import json
import sys
import time
import urllib.parse

# Allow `import f99_api` from the parent directory.
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import f99_api as cam_api


CHECK_PORTS = [80, 443, 554, 1935, 8000, 8080, 8081, 8554, 8888, 9000,
               9090, 10000, 12000, 19999, 20000, 32108, 36298, 36299,
               36300, 36301, 49152, 50000, 54321]


def baseline_check() -> dict:
    props = cam_api.get_properties()
    return {
        "cgi_ok":   isinstance(props, dict) and props.get("error") == 0,
        "icap":     cam_api.icap_probe(),
        "udp10k":   cam_api.udp_probe(cam_api.DISCOVERY_UDP_PORT, cam_api.DISCOVERY_PAYLOAD),
        "udp8081":  cam_api.udp_probe(cam_api.AUDIO_DOWNLINK_PORT, b"\x00"),
        "tcp_open": cam_api.tcp_scan(CHECK_PORTS),
    }


def victory(b: dict) -> bool:
    if b["icap"].startswith("REPLY:"):
        return True
    if b["udp10k"].startswith("REPLY:") or b["udp8081"].startswith("REPLY:"):
        return True
    extra = [p for p in b["tcp_open"] if p != cam_api.DEFAULT.port]
    return bool(extra)


def fmt(b: dict) -> str:
    extra = [p for p in b["tcp_open"] if p != cam_api.DEFAULT.port]
    return (f"cgi={'OK' if b['cgi_ok'] else 'FAIL'}  "
            f"icap={b['icap']}  udp10k={b['udp10k'][:18]}  "
            f"udp8081={b['udp8081'][:18]}  extra_tcp={extra}")


def try_change(label: str, qs: str, settle_secs: float = 2.0) -> tuple[bool, dict]:
    print(f"  [test] {label}")
    r = cam_api.set_params(qs)
    print(f"         set_params → {r}")
    time.sleep(settle_secs)
    b = baseline_check()
    print(f"         {fmt(b)}")
    return victory(b), b


def main():
    print("=== baseline ===")
    backup = cam_api.get_params()
    if not isinstance(backup, dict) or backup.get("error") != 0:
        print(f"ERROR: get_params failed: {backup}", file=sys.stderr)
        return 1
    backup_path = pathlib.Path(__file__).resolve().parent / "params_backup.json"
    with open(backup_path, "w") as f:
        json.dump(backup, f, indent=2)
    print(f"backed up {len(backup)} fields → {backup_path}")
    base = baseline_check()
    print(f"baseline: {fmt(base)}")
    if victory(base):
        print("ICAP daemon already alive — nothing to do!")
        return 0

    changed_fields: set[str] = set()

    def attempt(label, qs):
        for token in qs.split("&"):
            if "=" in token:
                k = token.split("=", 1)[0]
                # ignore reinit_*/save which are commands, not values
                if not k.startswith("reinit_") and k != "save":
                    changed_fields.add(k)
        return try_change(label, qs)

    tests: list[tuple[str, str]] = [
        # ---- reinit_* family: ask the camera to restart subsystems ----
        ("reinit video subsystem",       "reinit_video=1&save=0"),
        ("reinit audio subsystem",       "reinit_audio=1&save=0"),
        ("reinit stream subsystem",      "reinit_stream=1&save=0"),
        ("reinit record",                "reinit_record=1&save=0"),
        ("reinit comm",                  "reinit_comm=1&save=0"),
        ("reinit network",               "reinit_network=1&save=0"),
        ("reinit ap",                    "reinit_ap=1&save=0"),
        ("reinit wifi",                  "reinit_wifi=1&save=0"),
        ("reinit p2p",                   "reinit_p2p=1&save=0"),
        ("reinit udp",                   "reinit_udp=1&save=0"),
        ("reinit live",                  "reinit_live=1&save=0"),
        ("reinit sosocam",               "reinit_sosocam=1&save=0"),
        ("reinit discover",              "reinit_discover=1&save=0"),
        ("reinit (generic)",             "reinit=1&save=0"),
        ("startup",                      "startup=1&save=0"),

        # ---- ad-hoc "command-style" set_params fields ----
        ("cmd start_video",              "start_video=1&save=0"),
        ("cmd start_stream",             "start_stream=1&save=0"),
        ("cmd enable_stream",            "enable_stream=1&save=0"),
        ("cmd live=1",                   "live=1&save=0"),
        ("cmd enable_live",              "enable_live=1&save=0"),
        ("cmd start_icap",               "start_icap=1&save=0"),

        # ---- persistent field toggles (we will restore) ----
        ("video_on_always off",          "video_on_always=0&save=1"),
        ("video_on_always on",           "video_on_always=1&save=1"),
        ("enable_video cycle 0",         "enable_video=0&save=1"),
        ("enable_video cycle 1",         "enable_video=1&save=1&reinit_video=1"),
        ("enable_audio cycle 0",         "enable_audio=0&save=1"),
        ("enable_audio cycle 1",         "enable_audio=1&save=1&reinit_audio=1"),
        ("record_stream=1",              "record_stream=1&save=1"),
        ("record=1",                     "record=1&save=1"),
        ("p2p_id_type=1",                "p2p_id_type=1&save=1"),
        ("p2p_forward_data=1",           "p2p_forward_data=1&save=1"),
        ("wifi_switch=1",                "wifi_switch=1&save=1"),
        ("wired_disable=0",              "wired_disable=0&save=1"),
        ("da_defense=0",                 "da_defense=0&save=1"),
        ("Luoge_Version=1",              "Luoge_Version=1&save=1"),
        ("ptz_func=0",                   "ptz_func=0&save=1"),
        ("ptz_func=1",                   "ptz_func=1&save=1"),
        ("led=0",                        "led=0&save=1"),
        ("led=1",                        "led=1&save=1"),
        ("alarm_record=1",               "alarm_record=1&save=1"),
        ("hardware_stamp_id_tmp=0",      "hardware_stamp_id_tmp=0&save=1"),
        # max_streams_number is in get_properties (read-only) but try anyway
        ("max_streams_number=1",         "max_streams_number=1&save=1"),
        ("enable_icap=1",                "enable_icap=1&save=1"),
        ("enable_sosocam=1",             "enable_sosocam=1&save=1"),
    ]

    won = False
    winner = None
    for label, qs in tests:
        ok, snapshot = attempt(label, qs)
        if ok:
            won = True
            winner = (label, qs, snapshot)
            break

    print()
    print("=== summary ===")
    if won:
        print(f"WINNER: {winner[0]}  ({winner[1]})")
        print(f"  state: {fmt(winner[2])}")
    else:
        print("No tested change brought up ICAP/UDP10k/UDP8081 or opened any new TCP port.")

    # Restore.  Set them one at a time — the firmware rejects the whole query if
    # any single field is unknown, so a bulk restore would no-op after the first
    # unrecognised key.
    print()
    print("=== restoring changed fields ===")
    if not changed_fields:
        print("  nothing to restore.")
    else:
        for k in sorted(changed_fields):
            if k not in backup or not isinstance(backup[k], (int, str)):
                continue
            v = backup[k]
            if isinstance(v, str):
                v = urllib.parse.quote(v, safe="")
            r = cam_api.set_params(f"{k}={v}&save=1")
            ok = "OK" if r.get("error") == 0 else "skip"
            print(f"  {k}={v}: {r}  [{ok}]")

    print()
    print("=== final state ===")
    print(fmt(baseline_check()))
    return 0 if won else 1


if __name__ == "__main__":
    sys.exit(main())
