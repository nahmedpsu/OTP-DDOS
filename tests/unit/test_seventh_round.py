"""Regression tests for the seventh-round review.

M1 (the memory store keeps state as Redis does) is in test_store_parity.py. M4: a block's statistic
accumulates in processing order and a crossing is dated at the event that completes it; this is the
defined semantics (feedback.py module notes), not an equivalence to chronological execution, and the
reviewer's diagnostic is pinned here so the behaviour cannot change silently. Every test runs on the
memory store and on fakeredis."""


def _crossing(h, key, offsets):
    """Apply failures dated t0 + offset, in the given processing order, at t0 + 700 s; return the
    verdict relative to t0 (dated at, until)."""
    fb = h.p.feedback
    t0 = h.clock.now()
    h.clock.advance(700)
    for dt in offsets:
        fb._block_event(key, verified=False, event_id=f"{key}:{dt}", at=t0 + dt)
    v = fb.block_verdict(key)
    h.clock.advance(-700)
    return None if v is None else (v["at"] - t0, v["until"] - t0)


def test_block_statistic_accumulates_in_processing_order(h):
    """Failures dated 0, 1, 2, 3 and 603 s. In time order the fifth crossing failure is dated 603 s;
    processed in the order 0, 1, 2, 603, 3 the crossing is dated 3 s and its verdict expires 600 s
    earlier, although it contains the failure dated 603 s."""
    ttl = h.cfg.block_verdict_ttl
    assert _crossing(h, "block:96650831", [0, 1, 2, 3, 603]) == (603, 603 + ttl)
    assert _crossing(h, "block:96650832", [0, 1, 2, 603, 3]) == (3, 3 + ttl)
    doc = h.p.store.get("blocktest:block:96650832")
    assert doc["test_since"] == h.clock.now() + 3          # the next test starts at the earlier date
