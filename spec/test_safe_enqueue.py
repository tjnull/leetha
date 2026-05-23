"""Subscriber-queue safe enqueue (threadsafe broadcast path).

Regression: ``_broadcast_finding_threadsafe`` and the device_update
broadcast scheduled ``sub.put_nowait`` directly via
``loop.call_soon_threadsafe``. The surrounding ``try/except QueueFull``
only guarded *scheduling* — when the deferred callback actually ran and
the subscriber queue (maxsize=500) was full, ``put_nowait`` raised
``QueueFull`` inside an unguarded loop callback, surfacing as:

    Exception in callback Queue.put_nowait()
    asyncio.queues.QueueFull

The fix routes those broadcasts through ``_safe_enqueue``, which handles
``QueueFull`` itself (drop oldest, retry, then give up) so nothing ever
escapes into the event loop's exception handler.
"""

import asyncio

from leetha.app import _safe_enqueue


def test_safe_enqueue_into_open_queue():
    q = asyncio.Queue(maxsize=10)
    _safe_enqueue(q, {"type": "x"})
    assert q.get_nowait() == {"type": "x"}


def test_safe_enqueue_full_queue_drops_oldest_and_does_not_raise():
    q = asyncio.Queue(maxsize=1)
    q.put_nowait({"type": "old"})
    # Must NOT raise QueueFull
    _safe_enqueue(q, {"type": "new"})
    # Oldest dropped, newest retained
    assert q.get_nowait() == {"type": "new"}
    assert q.empty()


def test_safe_enqueue_is_callback_safe_under_call_soon():
    """Scheduling _safe_enqueue as a loop callback against a full queue
    must not log an 'Exception in callback' (i.e. must not raise inside
    the callback)."""
    async def run():
        loop = asyncio.get_running_loop()
        errors = []
        loop.set_exception_handler(lambda l, ctx: errors.append(ctx))

        q = asyncio.Queue(maxsize=1)
        q.put_nowait({"type": "old"})
        # Schedule the safe enqueue exactly like the broadcast path does.
        loop.call_soon(_safe_enqueue, q, {"type": "new"})
        await asyncio.sleep(0.01)  # let the callback run

        assert errors == [], f"callback raised into loop: {errors}"
        assert q.get_nowait() == {"type": "new"}

    asyncio.run(run())
