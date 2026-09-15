"""Duress subsystem: rolling-code authentication and escalation policy."""

from __future__ import annotations

import pytest

from core.config import get_settings
from core.duress import (
    CODED_ANNOUNCEMENTS,
    PUBLIC_BROADCAST_ELIGIBLE,
    STAFF_GUIDANCE,
    build_plan,
    commit_counter,
    derive_fob_code,
    verify_fob_activation,
)
from core.models import DuressKind

WINDOW = 32


def _code(device, counter: int, kind: str = "test") -> str:
    return derive_fob_code(device.shared_secret, device.serial, counter, kind)


# -------------------------------------------------------------- rolling code


def test_valid_activation_is_accepted(duress_device):
    result = verify_fob_activation(
        duress_device,
        counter=1,
        kind="test",
        code=_code(duress_device, 1),
        window=WINDOW,
    )
    assert result.ok is True
    assert result.counter == 1


def test_replayed_counter_is_rejected(duress_device):
    """A captured transmission must be worthless once the counter has moved."""
    first = verify_fob_activation(
        duress_device, counter=1, kind="test", code=_code(duress_device, 1), window=WINDOW
    )
    assert first.ok
    commit_counter(duress_device, 1)

    replay = verify_fob_activation(
        duress_device, counter=1, kind="test", code=_code(duress_device, 1), window=WINDOW
    )
    assert replay.ok is False
    assert replay.reason == "counter_replay"


def test_counter_at_stored_value_is_rejected(duress_device):
    duress_device.counter = 10
    result = verify_fob_activation(
        duress_device, counter=10, kind="test", code=_code(duress_device, 10), window=WINDOW
    )
    assert result.ok is False
    assert result.reason == "counter_replay"


def test_counter_far_ahead_is_rejected(duress_device):
    """Desynchronisation would silently disable a real fob, which is the worst outcome."""
    result = verify_fob_activation(
        duress_device,
        counter=5000,
        kind="test",
        code=_code(duress_device, 5000),
        window=WINDOW,
    )
    assert result.ok is False
    assert result.reason == "counter_out_of_window"


def test_counter_inside_window_is_accepted(duress_device):
    """Missed presses are normal, so a modest forward jump must still work."""
    result = verify_fob_activation(
        duress_device,
        counter=WINDOW,
        kind="test",
        code=_code(duress_device, WINDOW),
        window=WINDOW,
    )
    assert result.ok is True


def test_forged_code_is_rejected(duress_device):
    result = verify_fob_activation(
        duress_device, counter=1, kind="test", code="0" * 32, window=WINDOW
    )
    assert result.ok is False
    assert result.reason == "code_mismatch"


def test_code_is_bound_to_activation_kind(duress_device):
    """Otherwise a captured 'medical' press could be replayed as a 'threat' press."""
    medical_code = _code(duress_device, 1, kind="medical")
    result = verify_fob_activation(
        duress_device, counter=1, kind="threat", code=medical_code, window=WINDOW
    )
    assert result.ok is False
    assert result.reason == "code_mismatch"


def test_disabled_device_is_rejected(duress_device):
    duress_device.enabled = False
    result = verify_fob_activation(
        duress_device, counter=1, kind="test", code=_code(duress_device, 1), window=WINDOW
    )
    assert result.ok is False
    assert result.reason == "device_disabled"


def test_codes_differ_across_devices(session, store, duress_device):
    """A shared secret per device means one compromised fob does not compromise the rest."""
    from core.models import DuressDevice

    other = DuressDevice(
        store_id=store.id,
        serial="FOB-TEST-02",
        label="Second fob",
        shared_secret="c" * 64,
        counter=0,
    )
    session.add(other)
    session.commit()

    assert _code(duress_device, 1) != _code(other, 1)

    cross = verify_fob_activation(
        other, counter=1, kind="test", code=_code(duress_device, 1), window=WINDOW
    )
    assert cross.ok is False


def test_code_length_is_128_bits(duress_device):
    assert len(_code(duress_device, 1)) == 32  # hex characters


# ------------------------------------------------------------ escalation plan


def test_alerts_are_silent_by_default():
    """The design decision: a loud alarm escalates confrontation and endangers staff."""
    settings = get_settings()
    assert settings.duress_allow_public_broadcast is False

    plan = build_plan(DuressKind.THREAT.value, settings)
    assert plan.silent is True
    assert plan.public_broadcast is False


def test_public_broadcast_is_refused_when_disabled():
    settings = get_settings()
    plan = build_plan(
        DuressKind.THREAT.value, settings, request_public_broadcast=True
    )
    assert plan.public_broadcast is False
    assert plan.suppressed_broadcast_reason == "public_broadcast_disabled_by_configuration"


def test_public_broadcast_is_restricted_to_threat_events(monkeypatch):
    """Even with broadcast enabled, a suspected theft must not trigger a store-wide alarm."""
    settings = get_settings()
    monkeypatch.setattr(settings, "duress_allow_public_broadcast", True, raising=False)

    theft = build_plan(
        DuressKind.THEFT_IN_PROGRESS.value, settings, request_public_broadcast=True
    )
    assert theft.public_broadcast is False
    assert theft.suppressed_broadcast_reason == (
        "public_broadcast_not_permitted_for_this_activation_type"
    )

    threat = build_plan(DuressKind.THREAT.value, settings, request_public_broadcast=True)
    assert threat.public_broadcast is True
    assert threat.silent is False


def test_only_threat_is_broadcast_eligible():
    assert PUBLIC_BROADCAST_ELIGIBLE == frozenset({DuressKind.THREAT.value})


@pytest.mark.parametrize(
    "kind",
    [DuressKind.THREAT.value, DuressKind.THEFT_IN_PROGRESS.value, DuressKind.MEDICAL.value],
)
def test_every_real_activation_carries_guidance(kind: str):
    """Staff under stress need instructions, not just a siren."""
    plan = build_plan(kind, get_settings())
    assert plan.staff_guidance, f"no guidance for {kind}"
    assert plan.notify_roles


def test_threat_guidance_pushes_toward_de_escalation():
    guidance = " ".join(STAFF_GUIDANCE[DuressKind.THREAT.value]).lower()
    assert "do not confront" in guidance
    assert "999" in guidance


def test_theft_guidance_forbids_pursuit():
    guidance = " ".join(STAFF_GUIDANCE[DuressKind.THEFT_IN_PROGRESS.value]).lower()
    assert "never pursue" in guidance


def test_threat_notifies_everyone_including_assistants():
    """A duress alert that only reaches the manager fails if the manager is the one in
    trouble."""
    plan = build_plan(DuressKind.THREAT.value, get_settings())
    assert "assistant" in plan.notify_roles
    assert "duty_manager" in plan.notify_roles


def test_test_activation_makes_no_announcement():
    assert CODED_ANNOUNCEMENTS[DuressKind.TEST.value] == ""
    plan = build_plan(DuressKind.TEST.value, get_settings())
    assert plan.coded_announcement is None


def test_coded_announcements_do_not_name_the_incident():
    """A customer overhearing the announcement must not learn what is happening."""
    for kind in (DuressKind.THREAT.value, DuressKind.THEFT_IN_PROGRESS.value):
        announcement = CODED_ANNOUNCEMENTS[kind].lower()
        for word in ("theft", "shoplift", "steal", "police", "threat", "attack"):
            assert word not in announcement
