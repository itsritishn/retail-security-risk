"""Seed a demo store.

Idempotent: safe to run repeatedly. Existing records are left alone.

Credentials and device secrets are generated randomly at seed time, printed once, and
written to ``secrets/`` which is gitignored. Nothing is hardcoded, because a committed
default password is the single most common way a portfolio project becomes a real
vulnerability the moment someone deploys it.

Run with::

    python -m core.seed
"""

from __future__ import annotations

import json
import secrets as pysecrets
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from core import audit
from core.config import BASE_DIR
from core.db import init_db, session_scope
from core.models import Camera, DuressDevice, Role, Store, User, Zone
from core.security import hash_password
from core.util import new_secret

SECRETS_DIR = BASE_DIR / "secrets"

# Deliberately a fictional store. The reference deployment is a real shop, but naming an actual
# retailer in a public repository would imply an endorsement that does not exist, and would tie
# a named business to a discussion of its security gaps.
STORE_REFERENCE = "NORTHGATE-DEMO-001"
STORE_NAME = "Northgate Convenience (demo store)"

#: Zone risk weights encode shop-floor knowledge. These are the lines that actually walk
#: out of a UK convenience store: confectionery, chilled dairy, alcohol, and health and
#: beauty. Cadbury Dairy Milk is now sold from alarmed security boxes in some
#: supermarkets, which is as clear a signal as the sector gives about where the loss is.
ZONE_SPEC: tuple[dict, ...] = (
    {
        "code": "entrance",
        "name": "Front entrance",
        "risk_weight": 1.0,
        "is_high_value": False,
        "notes": "No guard on the door. Coverage here is the whole reason this exists.",
    },
    {
        "code": "confectionery",
        "name": "Confectionery",
        "risk_weight": 1.5,
        "is_high_value": True,
        "notes": "Highest loss category. Small, high value, easy to conceal.",
    },
    {
        "code": "chilled",
        "name": "Chilled and dairy",
        "risk_weight": 1.35,
        "is_high_value": True,
        "notes": "Butter, cheese, and premium meat.",
    },
    {
        "code": "alcohol",
        "name": "Beers, wines and spirits",
        "risk_weight": 1.55,
        "is_high_value": True,
        "notes": "Spirits especially. Often targeted by repeat offenders.",
    },
    {
        "code": "healthbeauty",
        "name": "Health and beauty",
        "risk_weight": 1.4,
        "is_high_value": True,
        "notes": "Razor blades, fragrance, vitamins.",
    },
    {
        "code": "ambient",
        "name": "Ambient grocery",
        "risk_weight": 0.9,
        "is_high_value": False,
        "notes": "Low loss. Weighted below baseline to keep prompts off browsing shoppers.",
    },
    {
        "code": "tills",
        "name": "Till area",
        "risk_weight": 1.0,
        "is_high_value": False,
        "notes": "Covered for staff safety rather than stock loss.",
    },
)

CAMERA_SPEC: tuple[tuple[str, str, str | None], ...] = (
    ("cam-entrance", "Entrance overview", "entrance"),
    ("cam-conf-01", "Confectionery aisle", "confectionery"),
    ("cam-chill-01", "Chilled run", "chilled"),
    ("cam-bws-01", "Beers, wines and spirits", "alcohol"),
    ("cam-hb-01", "Health and beauty", "healthbeauty"),
    ("cam-till-01", "Till and kiosk", "tills"),
)

USER_SPEC: tuple[tuple[str, str, str], ...] = (
    ("ritish", "Ritish N.", Role.ASSISTANT.value),
    ("dutymanager", "Duty Manager", Role.DUTY_MANAGER.value),
    ("admin", "System Administrator", Role.ADMIN.value),
    ("auditor", "Independent Auditor", Role.AUDITOR.value),
)

DEVICE_SPEC: tuple[tuple[str, str], ...] = (
    ("FOB-TILL-01", "Till lanyard fob"),
    ("FOB-FLOOR-01", "Floor-walker fob"),
    ("FOB-BACKDOOR-01", "Stock room fob"),
)


def _write_secrets_file(name: str, payload: dict) -> Path:
    """Write generated secrets with owner-only permissions."""
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    path = SECRETS_DIR / name
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _generate_passphrase() -> str:
    """Three-word style passphrase, per NCSC guidance on memorable length.

    Long and typeable beats short and cryptic on a shared till terminal, where a password
    that is awkward to type is a password that ends up written on a sticky note.
    """
    words = (
        "harbour", "lantern", "meadow", "cobble", "thistle", "kestrel", "bramble",
        "gable", "quarry", "tundra", "willow", "cinder", "beacon", "marrow",
    )
    picked = "-".join(pysecrets.choice(words) for _ in range(3))
    return f"{picked}-{pysecrets.randbelow(90) + 10}"


def seed() -> dict:
    init_db()
    report: dict = {"created": [], "existing": [], "credentials": {}, "camera_keys": {}}

    with session_scope() as session:
        store = _ensure_store(session, report)
        session.flush()

        zones = _ensure_zones(session, store, report)
        session.flush()

        camera_keys = _ensure_cameras(session, store, zones, report)
        credentials = _ensure_users(session, store, report)
        device_secrets = _ensure_devices(session, store, report)

        session.flush()

        audit.record(
            session,
            store_id=store.id,
            actor_type="system",
            actor_ref="seed",
            action="estate.seeded",
            detail={
                "zones": len(zones),
                "cameras": len(CAMERA_SPEC),
                "users": len(USER_SPEC),
                "devices": len(DEVICE_SPEC),
            },
        )

    report["credentials"] = credentials
    report["camera_keys"] = camera_keys

    if camera_keys:
        path = _write_secrets_file(
            "edge_credentials.json",
            {
                "core_url": "http://127.0.0.1:8000",
                "store_reference": STORE_REFERENCE,
                "cameras": camera_keys,
            },
        )
        report["edge_credentials_path"] = str(path)

    if device_secrets:
        path = _write_secrets_file("duress_devices.json", {"devices": device_secrets})
        report["duress_secrets_path"] = str(path)

    return report


def _ensure_store(session: Session, report: dict) -> Store:
    store = session.execute(
        select(Store).where(Store.reference == STORE_REFERENCE)
    ).scalar_one_or_none()

    if store is not None:
        report["existing"].append(f"store:{STORE_REFERENCE}")
        return store

    store = Store(name=STORE_NAME, reference=STORE_REFERENCE, timezone="Europe/London")
    session.add(store)
    report["created"].append(f"store:{STORE_REFERENCE}")
    return store


def _ensure_zones(session: Session, store: Store, report: dict) -> dict[str, Zone]:
    zones: dict[str, Zone] = {}

    for spec in ZONE_SPEC:
        existing = session.execute(
            select(Zone).where(Zone.store_id == store.id, Zone.code == spec["code"])
        ).scalar_one_or_none()

        if existing is not None:
            zones[spec["code"]] = existing
            report["existing"].append(f"zone:{spec['code']}")
            continue

        zone = Zone(store_id=store.id, **spec)
        session.add(zone)
        zones[spec["code"]] = zone
        report["created"].append(f"zone:{spec['code']}")

    return zones


def _ensure_cameras(
    session: Session, store: Store, zones: dict[str, Zone], report: dict
) -> dict[str, str]:
    keys: dict[str, str] = {}

    for code, name, zone_code in CAMERA_SPEC:
        existing = session.execute(
            select(Camera).where(Camera.store_id == store.id, Camera.code == code)
        ).scalar_one_or_none()

        if existing is not None:
            report["existing"].append(f"camera:{code}")
            keys[code] = existing.ingest_key
            continue

        zone = zones.get(zone_code) if zone_code else None
        ingest_key = new_secret(32)
        camera = Camera(
            store_id=store.id,
            zone_id=zone.id if zone else None,
            code=code,
            name=name,
            ingest_key=ingest_key,
        )
        session.add(camera)
        keys[code] = ingest_key
        report["created"].append(f"camera:{code}")

    return keys


def _ensure_users(session: Session, store: Store, report: dict) -> dict[str, dict]:
    credentials: dict[str, dict] = {}

    for username, display_name, role in USER_SPEC:
        existing = session.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()

        if existing is not None:
            report["existing"].append(f"user:{username}")
            continue

        password = _generate_passphrase()
        user = User(
            store_id=store.id,
            username=username,
            display_name=display_name,
            role=role,
            password_hash=hash_password(password),
            must_change_password=True,
        )
        session.add(user)
        credentials[username] = {"password": password, "role": role}
        report["created"].append(f"user:{username}")

    return credentials


def _ensure_devices(session: Session, store: Store, report: dict) -> dict[str, dict]:
    device_secrets: dict[str, dict] = {}

    for serial, label in DEVICE_SPEC:
        existing = session.execute(
            select(DuressDevice).where(DuressDevice.serial == serial)
        ).scalar_one_or_none()

        if existing is not None:
            report["existing"].append(f"device:{serial}")
            device_secrets[serial] = {
                "shared_secret": existing.shared_secret,
                "counter": existing.counter,
            }
            continue

        shared_secret = new_secret(32)
        device = DuressDevice(
            store_id=store.id,
            serial=serial,
            label=label,
            shared_secret=shared_secret,
            counter=0,
            battery_percent=100,
        )
        session.add(device)
        device_secrets[serial] = {"shared_secret": shared_secret, "counter": 0}
        report["created"].append(f"device:{serial}")

    return device_secrets


def main() -> None:
    report = seed()

    print("\nSentinelFloor seed complete")
    print("=" * 64)
    print(f"Created  : {len(report['created'])} records")
    print(f"Existing : {len(report['existing'])} records left untouched")

    if report["credentials"]:
        print("\nSign-in credentials (shown once, not stored anywhere in plaintext):")
        print("-" * 64)
        for username, info in report["credentials"].items():
            print(f"  {username:<14} {info['password']:<28} [{info['role']}]")
        print("\n  Every account is flagged must_change_password.")
    else:
        print("\nNo new users created. Existing passwords are unchanged and unrecoverable.")
        print("Delete sentinelfloor.db and re-seed if you need fresh credentials.")

    if report.get("edge_credentials_path"):
        print(f"\nEdge camera keys written to: {report['edge_credentials_path']}")
        print("  Mode 0600, inside a gitignored directory. Do not commit these.")

    if report.get("duress_secrets_path"):
        print(f"Duress fob secrets written to: {report['duress_secrets_path']}")

    print("\nNext:")
    print("  ./scripts/dev.sh serve     then open http://127.0.0.1:8000")
    print("  ./scripts/dev.sh demo      to replay a synthetic shift\n")


if __name__ == "__main__":
    main()
