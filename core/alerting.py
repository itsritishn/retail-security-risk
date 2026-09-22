"""Real-time alert fan-out over WebSocket.

The ingest path runs synchronously in a worker thread (SQLAlchemy's session is not
async-safe here), while WebSocket delivery is asynchronous. Rather than reaching across
that boundary with ``run_coroutine_threadsafe`` and its attendant loop-lifetime hazards,
sync producers drop messages onto a bounded thread-safe queue and a single async pump
task drains it.

The queue is bounded on purpose. An unbounded outbox in an alerting system converts a
detection storm into memory exhaustion, and a monitoring tool that dies under load
fails in exactly the situation it exists for. When the queue is full the newest message
is dropped and the drop is counted, and the counter is exposed on ``/healthz`` so the
condition is observable rather than silent.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import queue
from dataclasses import dataclass, field

from starlette.websockets import WebSocket, WebSocketState

logger = logging.getLogger("sentinelfloor.alerting")

OUTBOX_MAX = 1000


@dataclass
class HubStats:
    connections: int = 0
    published: int = 0
    delivered: int = 0
    dropped_queue_full: int = 0
    dropped_send_failed: int = 0

    def as_dict(self) -> dict:
        return {
            "connections": self.connections,
            "published": self.published,
            "delivered": self.delivered,
            "dropped_queue_full": self.dropped_queue_full,
            "dropped_send_failed": self.dropped_send_failed,
        }


@dataclass(eq=False)
class Subscriber:
    """One connected dashboard.

    ``eq=False`` is load-bearing, not stylistic. A plain ``@dataclass`` generates
    ``__eq__``, which causes Python to set ``__hash__ = None``, and subscribers are held in
    a ``set``. Without this the first WebSocket connection raises
    ``TypeError: unhashable type``.

    Identity semantics are also the correct semantics here: two connections from the same
    user on two devices are two distinct subscribers and both must receive alerts.
    """

    websocket: WebSocket
    store_id: int
    role: str
    user_ref: str


class AlertHub:
    """Fan-out hub scoped by store."""

    def __init__(self) -> None:
        self._subscribers: dict[int, set[Subscriber]] = {}
        self._outbox: queue.Queue[tuple[int, dict]] = queue.Queue(maxsize=OUTBOX_MAX)
        self._pump: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self.stats = HubStats()

    # -- lifecycle ---------------------------------------------------------------

    async def start(self) -> None:
        if self._pump is None or self._pump.done():
            self._pump = asyncio.create_task(self._run_pump(), name="alert-hub-pump")

    async def stop(self) -> None:
        if self._pump is not None:
            self._pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._pump
            self._pump = None

        async with self._lock:
            for subscribers in self._subscribers.values():
                for sub in list(subscribers):
                    with contextlib.suppress(Exception):
                        await sub.websocket.close()
            self._subscribers.clear()
            self.stats.connections = 0

    # -- subscription ------------------------------------------------------------

    async def subscribe(self, subscriber: Subscriber) -> None:
        async with self._lock:
            self._subscribers.setdefault(subscriber.store_id, set()).add(subscriber)
            self.stats.connections += 1
        logger.info(
            "hub subscribe store=%s role=%s user=%s",
            subscriber.store_id,
            subscriber.role,
            subscriber.user_ref,
        )

    async def unsubscribe(self, subscriber: Subscriber) -> None:
        async with self._lock:
            bucket = self._subscribers.get(subscriber.store_id)
            if bucket and subscriber in bucket:
                bucket.discard(subscriber)
                self.stats.connections = max(0, self.stats.connections - 1)
            if bucket is not None and not bucket:
                self._subscribers.pop(subscriber.store_id, None)

    # -- publishing --------------------------------------------------------------

    def publish(self, store_id: int, payload: dict) -> bool:
        """Enqueue a message from synchronous code. Never blocks, never raises."""
        try:
            self._outbox.put_nowait((store_id, payload))
        except queue.Full:
            self.stats.dropped_queue_full += 1
            logger.warning(
                "alert outbox full, dropped message store=%s kind=%s",
                store_id,
                payload.get("kind"),
            )
            return False
        self.stats.published += 1
        return True

    async def broadcast(self, store_id: int, payload: dict) -> None:
        """Send immediately to every eligible subscriber of one store."""
        async with self._lock:
            targets = list(self._subscribers.get(store_id, ()))

        if not targets:
            return

        audience: set[str] | None = None
        raw_roles = payload.get("notify_roles")
        if isinstance(raw_roles, list) and raw_roles:
            audience = {str(r) for r in raw_roles}

        stale: list[Subscriber] = []
        for sub in targets:
            if audience is not None and sub.role not in audience:
                continue
            if sub.websocket.client_state is not WebSocketState.CONNECTED:
                stale.append(sub)
                continue
            try:
                await sub.websocket.send_json(payload)
                self.stats.delivered += 1
            except Exception:  # noqa: BLE001 - one bad socket must not stop the fan-out
                self.stats.dropped_send_failed += 1
                stale.append(sub)

        for sub in stale:
            await self.unsubscribe(sub)

    async def _run_pump(self) -> None:
        """Drain the outbox onto connected sockets."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                store_id, payload = await loop.run_in_executor(
                    None, self._outbox.get, True, 0.5
                )
            except asyncio.CancelledError:
                raise
            except queue.Empty:
                continue
            except Exception:  # noqa: BLE001
                logger.exception("alert pump failed to dequeue")
                await asyncio.sleep(0.25)
                continue

            try:
                await self.broadcast(store_id, payload)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("alert pump failed to broadcast")


#: Process-wide hub. Single-process deployment only; a multi-worker rollout needs a
#: Redis pub/sub backplane so that a subscriber connected to worker A still receives
#: events ingested by worker B. Recorded as future work in docs/07-roadmap.md.
hub = AlertHub()


def alert_message(
    *,
    kind: str,
    payload: dict,
    notify_roles: list[str] | None = None,
) -> dict:
    """Envelope for every hub message so the client can dispatch on one field."""
    message: dict = {"kind": kind, "data": payload}
    if notify_roles:
        message["notify_roles"] = notify_roles
    return message
