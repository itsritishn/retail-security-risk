"""End-to-end API behaviour, including the access-control and anti-replay paths."""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.security import EDGE_SIGNATURE_HEADER, compute_edge_signature
from core.util import canonical_json, new_nonce, utcnow
from tests.conftest import TEST_PASSWORD, login

INGEST_KEY = "a" * 64  # matches the camera fixture
CAMERA_CODE = "cam-test-01"


def signed_event(**overrides) -> tuple[dict, dict]:
    """Build a valid signed event payload and its headers."""
    payload = {
        "camera_code": CAMERA_CODE,
        "event_type": "concealment",
        "track_ref": "track-abc",
        "raw_score": 0.95,
        "occurred_at": utcnow().isoformat(),
        "nonce": new_nonce(),
        "model_version": "test-1",
        "features": {"concealment_pattern": True, "peak_extension": 2.3},
    }
    payload.update(overrides)
    key = overrides.pop("_key", INGEST_KEY)
    signature = compute_edge_signature(key, payload)
    return payload, {
        EDGE_SIGNATURE_HEADER: signature,
        "Content-Type": "application/json",
    }


def post_event(client, payload: dict, headers: dict):
    """Send the exact canonical bytes that were signed."""
    return client.post(
        "/api/v1/events",
        content=canonical_json(payload).encode("utf-8"),
        headers=headers,
    )


# --------------------------------------------------------------------- health


def test_healthz_is_public(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_healthz_leaks_no_estate_detail(client):
    """The only unauthenticated route must not be a reconnaissance tool."""
    body = response_text = client.get("/healthz").text.lower()
    for leak in ("store", "camera", "zone", "user", "threshold", "sqlite"):
        assert leak not in body, response_text


def test_readyz_reports_database_health(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["checks"]["database"] == "ok"


# ------------------------------------------------------------- security headers


def test_security_headers_are_present(client):
    headers = client.get("/healthz").headers
    assert "content-security-policy" in headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "no-store" in headers["cache-control"]


def test_csp_forbids_inline_script(client):
    csp = client.get("/healthz").headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp


# ------------------------------------------------------------- authentication


def test_dashboard_redirects_when_signed_out(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_api_returns_401_when_signed_out(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_login_and_logout_flow(client):
    login(client)

    me = client.get("/api/v1/me")
    assert me.status_code == 200
    assert me.json()["username"] == "assistant"

    csrf = client.get("/api/v1/csrf").json()["csrf_token"]
    logout = client.post(
        "/logout", data={"csrf_token": csrf}, follow_redirects=False
    )
    assert logout.status_code == 303
    assert client.get("/api/v1/alerts").status_code == 401


def test_bad_credentials_give_a_generic_error(client):
    response = client.post(
        "/login",
        data={"username": "assistant", "password": "wrong"},
        follow_redirects=False,
    )
    assert response.status_code == 401
    body = response.text.lower()
    # Must not distinguish "no such user" from "wrong password".
    assert "not recognised" in body
    assert "no such user" not in body
    assert "incorrect password" not in body


def test_unknown_user_response_matches_bad_password_response(client):
    wrong_password = client.post(
        "/login",
        data={"username": "assistant", "password": "wrong"},
        follow_redirects=False,
    )
    unknown_user = client.post(
        "/login",
        data={"username": "ghost", "password": "wrong"},
        follow_redirects=False,
    )
    assert wrong_password.status_code == unknown_user.status_code


# ------------------------------------------------------------- event ingest


def test_signed_event_is_accepted_and_raises_an_alert(client):
    payload, headers = signed_event()
    response = post_event(client, payload, headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["alerted"] is True
    assert body["alert_id"] is not None
    assert body["severity"] in {"medium", "high"}


def test_event_without_signature_is_rejected(client):
    payload, _ = signed_event()
    response = client.post(
        "/api/v1/events",
        content=canonical_json(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401


def test_event_with_wrong_signature_is_rejected(client):
    payload, headers = signed_event()
    headers[EDGE_SIGNATURE_HEADER] = "0" * 64
    assert post_event(client, payload, headers).status_code == 401


def test_event_signed_with_the_wrong_key_is_rejected(client):
    payload = {
        "camera_code": CAMERA_CODE,
        "event_type": "concealment",
        "track_ref": "t",
        "raw_score": 0.9,
        "occurred_at": utcnow().isoformat(),
        "nonce": new_nonce(),
        "features": {},
    }
    headers = {
        EDGE_SIGNATURE_HEADER: compute_edge_signature("z" * 64, payload),
        "Content-Type": "application/json",
    }
    assert post_event(client, payload, headers).status_code == 401


def test_event_for_unknown_camera_is_rejected(client):
    payload, headers = signed_event(camera_code="cam-does-not-exist")
    assert post_event(client, payload, headers).status_code == 401


def test_stale_event_is_rejected(client):
    """Two-sided skew window: a back-dated event looks like a replay."""
    payload, headers = signed_event(
        occurred_at=(utcnow() - timedelta(minutes=10)).isoformat()
    )
    assert post_event(client, payload, headers).status_code == 401


def test_future_dated_event_is_rejected(client):
    payload, headers = signed_event(
        occurred_at=(utcnow() + timedelta(minutes=10)).isoformat()
    )
    assert post_event(client, payload, headers).status_code == 401


def test_replayed_nonce_is_rejected(client):
    payload, headers = signed_event()

    first = post_event(client, payload, headers)
    assert first.status_code == 200

    replay = post_event(client, payload, headers)
    assert replay.status_code == 409


def test_prohibited_feature_is_rejected(client):
    """The fairness guard, enforced at the network boundary."""
    payload, headers = signed_event(
        features={"concealment_pattern": True, "ethnicity": "redacted"}
    )
    response = post_event(client, payload, headers)
    assert response.status_code == 422
    assert "protected characteristic" in response.text


def test_unknown_field_is_rejected(client):
    """extra='forbid' stops an edge worker attaching anything unmodelled."""
    payload, headers = signed_event()
    payload["thumbnail"] = "not allowed"
    headers[EDGE_SIGNATURE_HEADER] = compute_edge_signature(INGEST_KEY, payload)
    assert post_event(client, payload, headers).status_code == 422


def test_oversized_body_is_rejected(client):
    payload, headers = signed_event(features={"blob": "x" * 40_000})
    response = post_event(client, payload, headers)
    assert response.status_code == 413


def test_out_of_range_score_is_rejected(client):
    payload, headers = signed_event(raw_score=1.5)
    assert post_event(client, payload, headers).status_code == 422


def test_heartbeat_updates_liveness_without_storing_an_event(client):
    payload, headers = signed_event(
        event_type="heartbeat", raw_score=0.0, features={}, track_ref="heartbeat"
    )
    response = post_event(client, payload, headers)

    assert response.status_code == 200
    body = response.json()
    assert body["event_id"] is None
    assert body["alerted"] is False


# ------------------------------------------------------------------- alerts


def _raise_alert(client) -> int:
    payload, headers = signed_event()
    response = post_event(client, payload, headers)
    assert response.status_code == 200
    return response.json()["alert_id"]


def test_alert_lifecycle(client):
    alert_id = _raise_alert(client)
    csrf = login(client)

    listing = client.get("/api/v1/alerts")
    assert listing.status_code == 200
    assert any(item["id"] == alert_id for item in listing.json())

    acknowledged = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge", headers={"X-SF-CSRF": csrf}
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"

    resolved = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"disposition": "true_positive_recovered", "note": "Item returned."},
        headers={"X-SF-CSRF": csrf},
    )
    assert resolved.status_code == 200
    assert resolved.json()["disposition"] == "true_positive_recovered"


def test_acknowledge_requires_csrf_token(client):
    alert_id = _raise_alert(client)
    login(client)

    response = client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
    assert response.status_code == 403
    assert "CSRF" in response.text


def test_acknowledge_rejects_a_foreign_csrf_token(client):
    alert_id = _raise_alert(client)
    login(client)

    response = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers={"X-SF-CSRF": "0" * 64},
    )
    assert response.status_code == 403


def test_false_positive_requires_a_note(client):
    """The only way to learn why the model was wrong."""
    alert_id = _raise_alert(client)
    csrf = login(client)

    without = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"disposition": "false_positive", "note": ""},
        headers={"X-SF-CSRF": csrf},
    )
    assert without.status_code == 422

    with_note = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"disposition": "false_positive", "note": "Customer put it back."},
        headers={"X-SF-CSRF": csrf},
    )
    assert with_note.status_code == 200


def test_alert_carries_its_rationale(client):
    """A prompt with no explanation cannot be shown to a member of staff."""
    _raise_alert(client)
    login(client)

    alert = client.get("/api/v1/alerts").json()[0]
    assert alert["rationale"]["contributions"]
    assert alert["rationale"]["human_review_required"] is True


def test_alerts_from_another_store_are_not_visible(client, session, store):
    """Store scoping comes from the session, never from a parameter."""
    from core.models import Alert, AlertStatus, Camera, Event, Store, Zone
    from core.util import hours_from_now

    other_store = Store(name="Other", reference="TEST-OTHER")
    session.add(other_store)
    session.flush()

    other_zone = Zone(store_id=other_store.id, code="z", name="Z")
    session.add(other_zone)
    session.flush()

    other_camera = Camera(
        store_id=other_store.id,
        zone_id=other_zone.id,
        code="cam-other",
        name="Other camera",
        ingest_key="f" * 64,
    )
    session.add(other_camera)
    session.flush()

    other_event = Event(
        store_id=other_store.id,
        camera_id=other_camera.id,
        zone_id=other_zone.id,
        event_type="concealment",
        track_ref="x",
        raw_score=0.99,
        features={},
        occurred_at=utcnow(),
        expires_at=hours_from_now(72),
        nonce="other-nonce",
    )
    session.add(other_event)
    session.flush()

    foreign_alert = Alert(
        store_id=other_store.id,
        event_id=other_event.id,
        zone_id=other_zone.id,
        score=0.99,
        severity="high",
        status=AlertStatus.OPEN.value,
        headline="Should not be visible",
        rationale={},
    )
    session.add(foreign_alert)
    session.commit()

    csrf = login(client)

    listing = client.get("/api/v1/alerts").json()
    assert all(item["id"] != foreign_alert.id for item in listing)

    # And it must be a 404, not a 403: confirming existence would be a leak in itself.
    blocked = client.post(
        f"/api/v1/alerts/{foreign_alert.id}/acknowledge", headers={"X-SF-CSRF": csrf}
    )
    assert blocked.status_code == 404


# --------------------------------------------------------------------- rbac


def test_assistant_cannot_read_the_audit_log(client):
    login(client, "assistant")
    assert client.get("/api/v1/admin/audit").status_code == 403


def test_auditor_can_verify_the_chain(client):
    login(client, "auditor")
    response = client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_auditor_cannot_acknowledge_alerts(client):
    """Oversight must not be able to act on the thing it oversees."""
    alert_id = _raise_alert(client)
    csrf = login(client, "auditor")

    response = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge", headers={"X-SF-CSRF": csrf}
    )
    assert response.status_code == 403


def test_auditor_cannot_run_retention(client):
    csrf = login(client, "auditor")
    response = client.post(
        "/api/v1/admin/retention/run", headers={"X-SF-CSRF": csrf}
    )
    assert response.status_code == 403


def test_assistant_cannot_resolve_duress(client):
    """An assistant can raise and acknowledge but not declare the incident over."""
    csrf = login(client, "assistant")

    raised = client.post(
        "/api/v1/duress/manual",
        json={"kind": "test"},
        headers={"X-SF-CSRF": csrf},
    )
    assert raised.status_code == 200
    activation_id = raised.json()["id"]

    response = client.post(
        f"/api/v1/duress/{activation_id}/resolve", headers={"X-SF-CSRF": csrf}
    )
    assert response.status_code == 403


def test_manager_can_resolve_duress(client):
    csrf = login(client, "manager")

    raised = client.post(
        "/api/v1/duress/manual",
        json={"kind": "test"},
        headers={"X-SF-CSRF": csrf},
    )
    activation_id = raised.json()["id"]

    response = client.post(
        f"/api/v1/duress/{activation_id}/resolve", headers={"X-SF-CSRF": csrf}
    )
    assert response.status_code == 200


def test_admin_policy_endpoint_states_the_constraints(client):
    """Documented in the API itself, so an auditor can confirm it without reading code."""
    login(client, "admin")
    policy = client.get("/api/v1/admin/policy").json()

    assert policy["biometric_processing"] == "none"
    assert policy["facial_recognition"] == "not implemented and out of scope"
    assert policy["automated_decision_making"].startswith("none")
    assert "ethnicity" in policy["prohibited_feature_keys"]


# -------------------------------------------------------------------- duress


def test_fob_activation_is_accepted(client, duress_device):
    from core.duress import derive_fob_code

    code = derive_fob_code(duress_device.shared_secret, duress_device.serial, 1, "threat")
    response = client.post(
        "/api/v1/duress/fob",
        json={
            "serial": duress_device.serial,
            "counter": 1,
            "kind": "threat",
            "code": code,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["silent"] is True
    assert body["public_broadcast"] is False
    assert body["staff_guidance"]


def test_replayed_fob_activation_is_rejected(client, duress_device):
    from core.duress import derive_fob_code

    code = derive_fob_code(duress_device.shared_secret, duress_device.serial, 1, "test")
    payload = {
        "serial": duress_device.serial,
        "counter": 1,
        "kind": "test",
        "code": code,
    }

    assert client.post("/api/v1/duress/fob", json=payload).status_code == 200
    assert client.post("/api/v1/duress/fob", json=payload).status_code == 401


def test_unknown_fob_gives_the_same_error_as_a_bad_code(client, duress_device):
    """Otherwise valid fob serials can be enumerated by brute force."""
    unknown = client.post(
        "/api/v1/duress/fob",
        json={"serial": "FOB-NOPE", "counter": 1, "kind": "test", "code": "0" * 32},
    )
    bad_code = client.post(
        "/api/v1/duress/fob",
        json={
            "serial": duress_device.serial,
            "counter": 1,
            "kind": "test",
            "code": "0" * 32,
        },
    )

    assert unknown.status_code == bad_code.status_code == 401
    assert unknown.json()["detail"] == bad_code.json()["detail"]


def test_public_broadcast_request_is_refused_by_configuration(client):
    csrf = login(client, "manager")
    response = client.post(
        "/api/v1/duress/manual",
        json={"kind": "threat", "request_public_broadcast": True},
        headers={"X-SF-CSRF": csrf},
    )
    assert response.status_code == 200
    assert response.json()["public_broadcast"] is False


def test_duress_device_secret_is_never_returned(client, duress_device):
    login(client, "manager")
    body = client.get("/api/v1/duress/devices").text
    assert duress_device.shared_secret not in body


# ------------------------------------------------------------------ analytics


def test_detection_quality_refuses_to_report_recall(client):
    """Recall is not computable from deployment data, so it must not be invented."""
    login(client, "manager")
    body = client.get("/api/v1/analytics/detection-quality").json()

    assert body["recall"] is None
    assert "not computable" in body["recall_note"]


def test_fairness_endpoint_states_what_it_cannot_measure(client):
    login(client, "manager")
    body = client.get("/api/v1/analytics/fairness").json()
    assert "Not measurable by design" in body["demographic_fairness"]


def test_assistant_cannot_read_analytics(client):
    login(client, "assistant")
    assert client.get("/api/v1/analytics/detection-quality").status_code == 403


# ------------------------------------------------------------------- audit


def test_ingest_and_actions_are_audited(client):
    alert_id = _raise_alert(client)
    csrf = login(client, "admin")

    client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers={"X-SF-CSRF": csrf})

    entries = client.get("/api/v1/admin/audit").json()
    actions = {entry["action"] for entry in entries}

    assert "alert.raised" in actions
    assert "alert.acknowledged" in actions
    assert "auth.login" in actions


def test_failed_ingest_authentication_is_audited(client):
    payload, headers = signed_event()
    headers[EDGE_SIGNATURE_HEADER] = "0" * 64
    post_event(client, payload, headers)

    login(client, "admin")
    # Recorded against store 0 because the store is unknown before authentication, so it
    # will not appear in a store-scoped listing. Verify directly instead.
    from sqlalchemy import select

    from core.db import SessionFactory
    from core.models import AuditRecord

    db = SessionFactory()
    try:
        rows = db.execute(
            select(AuditRecord).where(AuditRecord.action == "event.rejected")
        ).scalars().all()
        assert rows, "a rejected edge event must be audited"
        assert rows[0].outcome == "denied"
    finally:
        db.close()


def test_audit_chain_stays_valid_through_normal_use(client):
    alert_id = _raise_alert(client)
    csrf = login(client, "admin")

    client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers={"X-SF-CSRF": csrf})
    client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"disposition": "true_positive_recovered", "note": "ok"},
        headers={"X-SF-CSRF": csrf},
    )

    report = client.get("/api/v1/admin/audit/verify").json()
    assert report["ok"] is True
    assert report["entries_checked"] > 0


# ------------------------------------------------------------------ retention


def test_retention_removes_expired_events(client, session, camera):
    from core.models import Event
    from core.util import utcnow as now

    stale = Event(
        store_id=camera.store_id,
        camera_id=camera.id,
        zone_id=camera.zone_id,
        event_type="concealment",
        track_ref="old",
        raw_score=0.5,
        features={},
        occurred_at=now() - timedelta(days=10),
        expires_at=now() - timedelta(days=5),
        nonce="stale-nonce",
    )
    session.add(stale)
    session.commit()

    csrf = login(client, "admin")
    response = client.post(
        "/api/v1/admin/retention/run", headers={"X-SF-CSRF": csrf}
    )

    assert response.status_code == 200
    assert response.json()["events_removed"] >= 1


def test_validation_errors_do_not_echo_submitted_values(client):
    """A password or a rolling code must never come back in an error body."""
    response = client.post(
        "/api/v1/duress/fob",
        json={
            "serial": "FOB-TILL-01",
            "counter": -5,
            "kind": "test",
            "code": "secret-code-value-that-must-not-echo",
        },
    )
    assert response.status_code == 422
    assert "secret-code-value-that-must-not-echo" not in response.text
