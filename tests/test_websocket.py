"""Live alert feed.

This module exists because of a real defect. ``Subscriber`` was a plain dataclass, so Python
generated ``__eq__`` and set ``__hash__ = None``, and the hub stores subscribers in a ``set``.
Every WebSocket connection raised ``TypeError: unhashable type: 'Subscriber'``.

Nothing in the suite caught it, because the entire real-time path was untested. The whole
point of the system is that an alert reaches a member of staff within seconds, so that path
deserved coverage more than most.
"""

from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from core.security import EDGE_SIGNATURE_HEADER, compute_edge_signature
from core.util import canonical_json, new_nonce, utcnow
from tests.conftest import login

INGEST_KEY = "a" * 64
CAMERA_CODE = "cam-test-01"


def _signed_event(**overrides) -> tuple[dict, dict]:
    payload = {
        "camera_code": CAMERA_CODE,
        "event_type": "concealment",
        "track_ref": "ws-track",
        "raw_score": 0.95,
        "occurred_at": utcnow().isoformat(),
        "nonce": new_nonce(),
        "features": {"concealment_pattern": True},
    }
    payload.update(overrides)
    return payload, {
        EDGE_SIGNATURE_HEADER: compute_edge_signature(INGEST_KEY, payload),
        "Content-Type": "application/json",
    }


def test_operational_staff_can_connect(client):
    """The regression test for the unhashable-Subscriber defect."""
    login(client, "assistant")

    with client.websocket_connect("/ws/alerts") as ws:
        hello = ws.receive_json()
        assert hello["kind"] == "hello"
        assert hello["data"]["role"] == "assistant"


def test_ping_is_answered(client):
    login(client, "assistant")

    with client.websocket_connect("/ws/alerts") as ws:
        ws.receive_json()  # hello
        ws.send_text("ping")
        assert ws.receive_json()["kind"] == "pong"


def test_two_devices_both_connect(client):
    """Identity semantics: the same user on two devices is two subscribers, not one."""
    login(client, "assistant")

    with client.websocket_connect("/ws/alerts") as first:
        assert first.receive_json()["kind"] == "hello"
        with client.websocket_connect("/ws/alerts") as second:
            assert second.receive_json()["kind"] == "hello"


def test_unauthenticated_connection_is_refused(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/alerts") as ws:
            ws.receive_json()


def test_auditor_is_refused_on_the_live_feed(client):
    """Oversight is not an operational role, so it does not get the live alert stream."""
    login(client, "auditor")

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/alerts") as ws:
            ws.receive_json()


def test_alert_reaches_a_connected_dashboard(client):
    """End-to-end: signed event in, alert out over the socket.

    This is the behaviour the product is for. Ingest runs in a worker thread and publishes to
    a queue; an async pump drains it onto sockets. That hand-off across the sync/async
    boundary is the part most likely to break silently, and only this test would notice.
    """
    login(client, "assistant")

    with client.websocket_connect("/ws/alerts") as ws:
        assert ws.receive_json()["kind"] == "hello"

        payload, headers = _signed_event()
        response = client.post(
            "/api/v1/events",
            content=canonical_json(payload).encode("utf-8"),
            headers=headers,
        )
        assert response.status_code == 200, response.text
        assert response.json()["alerted"] is True

        message = ws.receive_json()
        assert message["kind"] == "alert.new"

        data = message["data"]
        assert data["id"] == response.json()["alert_id"]
        assert data["severity"] in {"medium", "high"}
        assert data["zone"] == "Confectionery"
        # The rationale travels with the alert: a prompt with no explanation is not
        # something a member of staff can act on.
        assert data["rationale"]["contributions"]


def test_suppressed_event_produces_no_message(client):
    """A below-threshold event must not reach the dashboard at all."""
    login(client, "assistant")

    with client.websocket_connect("/ws/alerts") as ws:
        ws.receive_json()  # hello

        payload, headers = _signed_event(raw_score=0.1, features={})
        response = client.post(
            "/api/v1/events",
            content=canonical_json(payload).encode("utf-8"),
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["alerted"] is False

        ws.send_text("ping")
        # Only the pong comes back. An alert frame arriving here would mean the policy
        # engine's suppression decision was not respected by the fan-out.
        assert ws.receive_json()["kind"] == "pong"


def test_hub_counts_deliveries(client):
    from core.alerting import hub

    login(client, "assistant")
    before = hub.stats.delivered

    with client.websocket_connect("/ws/alerts") as ws:
        ws.receive_json()
        payload, headers = _signed_event()
        client.post(
            "/api/v1/events",
            content=canonical_json(payload).encode("utf-8"),
            headers=headers,
        )
        ws.receive_json()

    assert hub.stats.delivered > before
