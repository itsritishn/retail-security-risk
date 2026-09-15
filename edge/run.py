"""Edge worker CLI.

    python -m edge.run --camera cam-conf-01
    python -m edge.run --camera cam-conf-01 --realtime
    python -m edge.run --camera cam-conf-01 --dry-run     # score locally, publish nothing
    python -m edge.run --all --realtime                   # every configured camera

Ingest keys are read from ``secrets/edge_credentials.json``, written by ``python -m core.seed``.
They are never taken from the command line, because arguments are visible in the process list
to every user on the machine.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml

from core.config import BASE_DIR
from edge.pipeline import EdgePipeline

logger = logging.getLogger("sentinelfloor.edge")

DEFAULT_CONFIG = BASE_DIR / "edge" / "config.yaml"
CREDENTIALS_PATH = BASE_DIR / "secrets" / "edge_credentials.json"


def load_config(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"Edge config not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_credentials(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"Camera ingest keys not found at {path}\n\n"
            "Run the seeder first:\n"
            "    python -m core.seed"
        )
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return dict(payload.get("cameras") or {})


def build_pipeline_config(
    config: dict, credentials: dict, camera_code: str, *, dry_run: bool
) -> dict:
    if camera_code not in credentials and not dry_run:
        available = ", ".join(sorted(credentials)) or "none"
        raise SystemExit(
            f"No ingest key for camera {camera_code!r}.\n"
            f"Cameras with keys: {available}\n"
            "Re-run `python -m core.seed`, or use --dry-run to score without publishing."
        )

    return {
        "camera_code": camera_code,
        "ingest_key": credentials.get(camera_code, "dry-run-no-key"),
        "core_url": config.get("core_url", "http://127.0.0.1:8000"),
        "backend": config.get("backend", "synthetic"),
        "backend_options": config.get("backend_options") or {},
        "heartbeat_seconds": config.get("heartbeat_seconds", 60),
        "publish_floor": config.get("publish_floor", 0.35),
        "iou_threshold": config.get("iou_threshold", 0.25),
        "max_missed_frames": config.get("max_missed_frames", 8),
        "max_track_age_seconds": config.get("max_track_age_seconds", 180),
        "dry_run": dry_run,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="edge.run",
        description="SentinelFloor edge worker: pose in, signed behavioural events out.",
    )
    parser.add_argument("--camera", help="Camera code to run, e.g. cam-conf-01")
    parser.add_argument(
        "--all", action="store_true", help="Run every camera listed in the config, in turn"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Pace frames against wall clock so alerts appear at a human rate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Score locally and log results without publishing anything",
    )
    parser.add_argument("--frames", type=int, help="Stop after this many frames")
    parser.add_argument(
        "--seed", type=int, help="Override the synthetic backend seed for a different shift"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
    )

    if not args.camera and not args.all:
        raise SystemExit("Specify --camera CODE or --all")

    config = load_config(args.config)
    credentials = {} if args.dry_run else load_credentials(CREDENTIALS_PATH)

    if args.seed is not None:
        config.setdefault("backend_options", {})["seed"] = args.seed

    if args.all:
        camera_codes = [
            str(entry["camera_code"])
            for entry in (config.get("cameras") or [])
            if entry.get("camera_code")
        ]
        if not camera_codes:
            raise SystemExit("No cameras listed in the config file")
    else:
        camera_codes = [args.camera]

    overall_alerts = 0
    overall_events = 0

    for index, camera_code in enumerate(camera_codes):
        pipeline_config = build_pipeline_config(
            config, credentials, camera_code, dry_run=args.dry_run
        )

        # A different seed per camera, otherwise every aisle sees the identical shift and
        # the analytics look suspiciously tidy.
        options = dict(pipeline_config["backend_options"])
        if "seed" in options:
            options["seed"] = int(options["seed"]) + index * 977
            pipeline_config["backend_options"] = options

        pipeline = EdgePipeline.from_config(pipeline_config)
        stats = pipeline.run(realtime=args.realtime, frame_limit=args.frames)

        overall_alerts += stats.alerts_raised
        overall_events += stats.events_published

        print(f"\n--- {camera_code} ---")
        for key, value in stats.as_dict().items():
            print(f"  {key:<24} {value}")
        if not args.dry_run:
            for key, value in pipeline.publisher.stats.as_dict().items():
                print(f"  publisher.{key:<14} {value}")
            if pipeline.publisher.pending_retries:
                print(f"  pending_retries          {pipeline.publisher.pending_retries}")

    print("\n" + "=" * 52)
    print(f"  events published : {overall_events}")
    print(f"  alerts raised    : {overall_alerts}")
    print("=" * 52)

    if not args.dry_run:
        print("\nOpen http://127.0.0.1:8000 to work the queue.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
