"""Pose extraction backends.

``synthetic`` needs no ML dependencies and is the default, so the full pipeline is
runnable and testable on any machine. ``yolo_pose`` performs real inference and is
imported lazily, so a missing PyTorch install is not an import error for everyone else.
"""

from __future__ import annotations

from edge.backends.base import PoseBackend, PoseDetection, PoseFrame

__all__ = ["PoseBackend", "PoseDetection", "PoseFrame", "build_backend"]


def build_backend(name: str, config: dict) -> PoseBackend:
    """Instantiate a backend by name.

    Imports are deferred so that selecting ``synthetic`` never touches the optional
    heavyweight dependencies.
    """
    normalised = (name or "synthetic").strip().lower()

    if normalised == "synthetic":
        from edge.backends.synthetic import SyntheticBackend

        return SyntheticBackend(config)

    if normalised in {"yolo_pose", "yolo", "ultralytics"}:
        try:
            from edge.backends.yolo_pose import YoloPoseBackend
        except ImportError as exc:
            raise RuntimeError(
                "The yolo_pose backend needs the optional edge dependencies:\n"
                "    pip install -r requirements-edge.txt\n"
                f"Original error: {exc}"
            ) from exc

        return YoloPoseBackend(config)

    raise ValueError(f"Unknown pose backend: {name!r}. Use 'synthetic' or 'yolo_pose'.")
