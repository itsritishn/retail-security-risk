"""Duress fob simulator.

Stands in for the radio gateway that would relay a physical button press. Useful for
demonstrating the duress path, and equally useful for demonstrating that the rolling-code
authentication actually works.

    python -m scripts.duress_fob_sim --list
    python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test
    python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind threat --zone confectionery

Attack simulations, for showing the controls hold:

    python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --replay
        Re-sends the previous counter value. Rejected: counter_replay.

    python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --forge
        Sends a plausible but incorrectly signed code. Rejected: code_mismatch.

    python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --desync
        Jumps the counter far ahead, the attack that would otherwise silently disable a
        real fob. Rejected: counter_out_of_window.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

from core.config import BASE_DIR
from core.duress import derive_fob_code

SECRETS_PATH = BASE_DIR / "secrets" / "duress_devices.json"
DEFAULT_CORE_URL = "http://127.0.0.1:8000"


def load_devices() -> dict:
    if not SECRETS_PATH.exists():
        raise SystemExit(
            f"Fob secrets not found at {SECRETS_PATH}\n"
            "Run the seeder first:\n    python -m core.seed"
        )
    with SECRETS_PATH.open("r", encoding="utf-8") as handle:
        return dict(json.load(handle).get("devices") or {})


def current_counter(serial: str) -> int:
    """Read the counter the core service currently holds for this device.

    A real fob keeps its own counter in non-volatile memory. Reading it from the database
    here keeps the simulator in step across runs without having to track state in a file.
    """
    from sqlalchemy import select

    from core.db import SessionFactory
    from core.models import DuressDevice

    session = SessionFactory()
    try:
        device = session.execute(
            select(DuressDevice).where(DuressDevice.serial == serial)
        ).scalar_one_or_none()
        return int(device.counter) if device else 0
    finally:
        session.close()


def send(core_url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{core_url.rstrip('/')}/api/v1/duress/fob",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "sentinelfloor-fob-sim"},
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"detail": raw[:400]}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SystemExit(
            f"Could not reach the core service at {core_url}: {exc}\n"
            "Start it with: ./scripts/dev.sh serve"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts.duress_fob_sim",
        description="Simulate a duress fob activation, including failed attacks.",
    )
    parser.add_argument("--serial", help="Fob serial, e.g. FOB-TILL-01")
    parser.add_argument(
        "--kind",
        default="test",
        choices=("threat", "theft_in_progress", "medical", "test"),
    )
    parser.add_argument("--zone", help="Zone code, e.g. confectionery")
    parser.add_argument("--core-url", default=DEFAULT_CORE_URL)
    parser.add_argument("--list", action="store_true", help="List known fobs and exit")

    attacks = parser.add_mutually_exclusive_group()
    attacks.add_argument(
        "--replay", action="store_true", help="Re-send a used counter (expect rejection)"
    )
    attacks.add_argument(
        "--forge", action="store_true", help="Send a wrongly signed code (expect rejection)"
    )
    attacks.add_argument(
        "--desync",
        action="store_true",
        help="Jump the counter far ahead (expect rejection)",
    )

    args = parser.parse_args(argv)
    devices = load_devices()

    if args.list or not args.serial:
        print("\nKnown duress fobs:")
        for serial in sorted(devices):
            print(f"  {serial:<20} counter={current_counter(serial)}")
        print("\nUse --serial SERIAL --kind KIND to activate.\n")
        return 0

    if args.serial not in devices:
        raise SystemExit(f"Unknown fob {args.serial!r}. Use --list to see available fobs.")

    shared_secret = str(devices[args.serial]["shared_secret"])
    stored = current_counter(args.serial)

    if args.replay:
        counter = stored
        code = derive_fob_code(shared_secret, args.serial, counter, args.kind)
        scenario = "replay of an already-used counter"
    elif args.forge:
        counter = stored + 1
        code = secrets.token_hex(16)
        scenario = "forged code without the shared secret"
    elif args.desync:
        counter = stored + 5000
        code = derive_fob_code(shared_secret, args.serial, counter, args.kind)
        scenario = "counter desynchronisation attempt"
    else:
        counter = stored + 1
        code = derive_fob_code(shared_secret, args.serial, counter, args.kind)
        scenario = "legitimate activation"

    payload = {
        "serial": args.serial,
        "counter": counter,
        "kind": args.kind,
        "code": code,
    }
    if args.zone:
        payload["zone_code"] = args.zone

    print(f"\nScenario  : {scenario}")
    print(f"Fob       : {args.serial}")
    print(f"Kind      : {args.kind}")
    print(f"Counter   : {counter} (core holds {stored})")

    status, body = send(args.core_url, payload)

    print(f"\nHTTP {status}")

    if status == 200:
        print(f"  Activation id     : {body.get('id')}")
        print(f"  Silent            : {body.get('silent')}")
        print(f"  Public broadcast  : {body.get('public_broadcast')}")
        if body.get("coded_announcement"):
            print(f"  Coded announcement: {body['coded_announcement']}")
        guidance = body.get("staff_guidance") or []
        if guidance:
            print("  Staff guidance:")
            for line in guidance:
                print(f"    - {line}")
        print("\n  Delivered to every connected dashboard.")
    else:
        print(f"  Rejected: {body.get('detail')}")
        print(
            "\n  The response is intentionally generic. A specific reason would let an "
            "attacker\n  distinguish an unknown serial from a bad code and enumerate valid "
            "fobs. The\n  precise cause is in the audit log, visible to an admin or auditor "
            "at\n  /api/v1/admin/audit?action=duress.rejected"
        )

    print()
    return 0 if status == 200 else 2


if __name__ == "__main__":
    sys.exit(main())
