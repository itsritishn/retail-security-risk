"""Staff duress subsystem.

Two design decisions here matter more than the code.

**Rolling-code authentication.** A fob that transmits a fixed identifier can be captured
and replayed by anyone with a cheap software-defined radio, which turns the panic button
into a way to summon staff away from wherever the attacker wants them. Each activation
therefore carries a monotonically increasing counter authenticated with HMAC-SHA256
under a per-device secret. A captured transmission is worthless once the counter moves.

**Silent by default.** The original concept for this system was a store-wide speaker
alarm. That was reversed. UK retailers recorded roughly 1,600 violence and abuse
incidents against staff per day in the BRC's 2026 survey, and a loud public alarm
escalates a theft into a confrontation with the member of staff standing closest. The
default is a silent alert to the duty manager and floor team plus an optional coded
announcement that means something to staff and nothing to a customer, which is how real
retail security operates. The public broadcast path still exists, but it is off by
default, requires explicit configuration, and is restricted to threat-to-person events.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.config import Settings
from core.models import DuressDevice, DuressKind, Role
from core.util import constant_time_equals, hmac_sha256_hex, utcnow

#: Length of the transmitted authenticator in hex characters (128 bits).
CODE_LENGTH = 32


# --------------------------------------------------------------------------------------
# Rolling code
# --------------------------------------------------------------------------------------


def derive_fob_code(shared_secret: str, serial: str, counter: int, kind: str) -> str:
    """Compute the authenticator a fob transmits for a given activation.

    Binding ``kind`` into the MAC matters: without it, a captured "medical" activation
    could be replayed as a "threat" activation at the attacker's choosing.
    """
    message = f"{serial}:{counter}:{kind}"
    return hmac_sha256_hex(shared_secret, message)[:CODE_LENGTH]


@dataclass
class DuressVerification:
    ok: bool
    reason: str
    counter: int | None = None


def verify_fob_activation(
    device: DuressDevice,
    *,
    counter: int,
    kind: str,
    code: str,
    window: int,
) -> DuressVerification:
    """Authenticate a fob activation against its stored counter.

    The counter must move strictly forward, and no further than ``window`` steps. Both
    bounds are load-bearing:

    * Accepting a counter at or below the stored value permits straightforward replay.
    * Accepting an unbounded jump forward lets an attacker who observes one valid
      transmission fast-forward the counter to near its maximum, desynchronising the
      real fob and silently disabling it. Denial of the panic button is the most
      damaging attack on this subsystem, so it is bounded explicitly.
    """
    if not device.enabled:
        return DuressVerification(False, "device_disabled")

    if counter <= device.counter:
        return DuressVerification(False, "counter_replay")

    if counter > device.counter + window:
        return DuressVerification(False, "counter_out_of_window")

    expected = derive_fob_code(device.shared_secret, device.serial, counter, kind)
    if not constant_time_equals(code, expected):
        return DuressVerification(False, "code_mismatch")

    return DuressVerification(True, "ok", counter=counter)


def commit_counter(device: DuressDevice, counter: int) -> None:
    """Advance the stored counter after a successful verification."""
    device.counter = counter
    device.last_seen_at = utcnow()


# --------------------------------------------------------------------------------------
# Escalation planning
# --------------------------------------------------------------------------------------

#: Coded announcements. Meaningful to briefed staff, unremarkable to a customer.
#: Wording follows the pattern UK retailers already use, so it needs no new training.
CODED_ANNOUNCEMENTS: dict[str, str] = {
    DuressKind.THREAT.value: "Would Mr Sands please come to the front of store.",
    DuressKind.THEFT_IN_PROGRESS.value: "Customer service assistance required, aisle team.",
    DuressKind.MEDICAL.value: "First aider to the shop floor, please.",
    DuressKind.TEST.value: "",
}

#: Guidance shown alongside the alert. Written to be read in three seconds under stress.
#: Every line pushes toward de-escalation, because the member of staff reading it is
#: usually alone, usually young, and is not a security officer.
STAFF_GUIDANCE: dict[str, list[str]] = {
    DuressKind.THREAT.value: [
        "Do not confront. Put a counter or shelving between you and the person.",
        "Keep the exit clear. Never block a doorway or follow anyone outside.",
        "Call 999 if anyone is in immediate danger. Say the store name and address first.",
        "Note clothing and direction of travel only when it is safe to do so.",
        "Move colleagues and customers away from the area rather than toward it.",
    ],
    DuressKind.THEFT_IN_PROGRESS.value: [
        "Approach only if you feel safe, and only in pairs.",
        "Open with a service line: offer a basket or ask if they need help finding anything.",
        "Do not touch the person, their bag, or their trolley.",
        "Never pursue beyond the door. Stock is replaceable and you are not.",
        "Log the outcome afterwards so the detection can be tuned.",
    ],
    DuressKind.MEDICAL.value: [
        "Send the nearest trained first aider to the location.",
        "Call 999 for anything involving breathing, chest pain, or loss of consciousness.",
        "Clear space around the person and keep the aisle free for responders.",
    ],
    DuressKind.TEST.value: [
        "This is a scheduled test. No response is required.",
        "Confirm the alert reached every signed-in device, then resolve it.",
    ],
}

#: Roles notified per activation type.
NOTIFY_MATRIX: dict[str, list[str]] = {
    DuressKind.THREAT.value: [
        Role.ASSISTANT.value,
        Role.DUTY_MANAGER.value,
        Role.ADMIN.value,
    ],
    DuressKind.THEFT_IN_PROGRESS.value: [Role.ASSISTANT.value, Role.DUTY_MANAGER.value],
    DuressKind.MEDICAL.value: [
        Role.ASSISTANT.value,
        Role.DUTY_MANAGER.value,
        Role.ADMIN.value,
    ],
    DuressKind.TEST.value: [Role.DUTY_MANAGER.value],
}

#: Only a threat to a person can ever justify a store-wide public alarm, and even then
#: it must be explicitly enabled in configuration.
PUBLIC_BROADCAST_ELIGIBLE = frozenset({DuressKind.THREAT.value})


@dataclass
class DuressPlan:
    kind: str
    silent: bool
    public_broadcast: bool
    coded_announcement: str | None
    notify_roles: list[str] = field(default_factory=list)
    staff_guidance: list[str] = field(default_factory=list)
    suppressed_broadcast_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "silent": self.silent,
            "public_broadcast": self.public_broadcast,
            "coded_announcement": self.coded_announcement,
            "notify_roles": self.notify_roles,
            "staff_guidance": self.staff_guidance,
            "suppressed_broadcast_reason": self.suppressed_broadcast_reason,
        }


def build_plan(
    kind: str,
    settings: Settings,
    *,
    request_public_broadcast: bool = False,
) -> DuressPlan:
    """Decide how an activation is delivered.

    Returns the plan rather than performing it, so the decision is unit testable and the
    same logic serves the fob path, the dashboard path, and the scheduled test path.
    """
    announcement = CODED_ANNOUNCEMENTS.get(kind) or None
    guidance = list(STAFF_GUIDANCE.get(kind, []))
    roles = list(NOTIFY_MATRIX.get(kind, [Role.DUTY_MANAGER.value]))

    public = False
    suppressed: str | None = None

    if request_public_broadcast:
        if not settings.duress_allow_public_broadcast:
            suppressed = "public_broadcast_disabled_by_configuration"
        elif kind not in PUBLIC_BROADCAST_ELIGIBLE:
            suppressed = "public_broadcast_not_permitted_for_this_activation_type"
        else:
            public = True

    return DuressPlan(
        kind=kind,
        silent=settings.duress_silent_first and not public,
        public_broadcast=public,
        coded_announcement=announcement,
        notify_roles=roles,
        staff_guidance=guidance,
        suppressed_broadcast_reason=suppressed,
    )
