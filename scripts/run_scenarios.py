#!/usr/bin/env python3
"""Run the attack and user scenarios from docs/problem_statement.md against the pipeline
on fakes and write results/scenarios.{md,json}. Deterministic (seeded RNG, fake clock).

    python3 scripts/run_scenarios.py [--backend memory|redis]
"""
import argparse
import json
import pathlib
import random
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.services import IpInfo   # noqa: E402
from otp_guard.testing import Harness   # noqa: E402


def new_harness(backend):
    h = Harness(backend=backend)
    if backend == "redis":
        time.time = h.clock.now            # fakeredis expires keys by wall clock
    return h


def attacker_request(h, **kw):
    """A rotating attacker presents a fresh fingerprint every time; it cannot be hours old."""
    tok, _ = h.session("web", age_hours=0)
    return h.web_request(session=tok, **kw)


def scenario_single_client_random_numbers(backend):
    h = new_harness(backend); tok, _ = h.session(); rng = random.Random(1)
    n = 200
    for _ in range(n):
        h.send(h.web_request(session=tok, mobile=f"9665{rng.randrange(10**8):08d}"))
    return dict(requests=n, sms_sent=h.sms_sent,
                note="The original incident: one client, random numbers. Stopped by the per-session cap (3 per 10 min).")


def scenario_datacenter_ip_rotation(backend, lift_caps):
    h = new_harness(backend)
    if lift_caps:
        h.lift_source_caps()
    h.svc.ip_intel.register("203.0.0.0/8", IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True, country="DE"))
    rng = random.Random(2); n = 300
    for i in range(n):
        h.send(attacker_request(h, ip=f"203.{i % 256}.{(i * 13) % 256}.{(i * 7) % 250 + 1}", mobile=f"9665{rng.randrange(10**8):08d}"))
    return dict(requests=n, sms_sent=h.sms_sent,
                note=("Source caps lifted: the datacenter ASN cap (50/min) alone bounds it." if lift_caps
                      else "Default config: the web source cap (5/min) bounds it."))


def scenario_residential_rotation_feedback(backend):
    h = new_harness(backend); h.lift_source_caps(); h.cfg.asn_limit_default = 100000
    h.svc.ip_intel.register("100.64.0.0/10", IpInfo(asn="AS9000", asn_type="residential"))
    rng = random.Random(3); per_minute = []
    for minute in range(20):
        before = h.sms_sent
        for i in range(30):
            k = minute * 30 + i
            h.send(attacker_request(h, ip=f"100.{64 + (k // 65536) % 64}.{(k // 256) % 256}.{k % 256}",
                                    mobile=f"9665{rng.randrange(10**8):08d}"))
        h.clock.advance(60); h.p.feedback.run_due_timeouts(); per_minute.append(h.sms_sent - before)
    return dict(requests=600, sms_sent=h.sms_sent, sms_per_minute=per_minute,
                asn_denylisted=h.p.store.exists("deny:asn:AS9000"),
                note="Every static limit removed; unique residential IP per request. Only the verification feedback loop sees it.")


def scenario_sms_pumping(backend):
    h = new_harness(backend); n = 50
    for i in range(n):
        h.send(attacker_request(h, ip=f"198.60.{i}.1", mobile=f"96699{i:07d}"))
    return dict(requests=n, sms_sent=h.sms_sent, note="Premium-rate prefix 96699: blocked at Step 5b.")


def scenario_sequential_walk(backend):
    """Distributed walk through 966501000000.. from a fresh IP and session each time, with every
    source cap lifted so only number intelligence and the feedback loop are in play."""
    h = new_harness(backend); h.lift_source_caps()
    for i in range(40):
        h.send(attacker_request(h, ip=f"198.61.{i}.1", mobile=f"966501{i:06d}"))
    phase1_sent = h.sms_sent
    flagged = sum(1 for lid in range(1, phase1_sent + 1)
                  if "narrow_range_burst" in (h.p.sms_history.get(lid) or {}).get("signals", []))
    h.clock.advance(601); h.p.feedback.run_due_timeouts()          # nobody verified anything
    before = h.sms_sent
    for i in range(40, 50):
        h.send(attacker_request(h, ip=f"198.61.{i}.1", mobile=f"966501{i:06d}"))
    return dict(requests=50, sms_sent=h.sms_sent, phase1_sent=phase1_sent, phase1_flagged_narrow_range=flagged,
                phase2_sent_after_feedback=h.sms_sent - before,
                note="Caps lifted; fresh fingerprint per request (+20). Phase 1: young fingerprint plus the narrow-range "
                     "signal reach only the delay tier, which still sends. Phase 2, after the 10-minute verification "
                     "window with zero conversions, the conversion penalty (+25) stacks on top and every further "
                     "request lands in the challenge tier: no more SMS.")


def scenario_legitimate_user(backend):
    h = new_harness(backend); tok, fp = h.session()
    r = h.send(h.web_request(session=tok))
    code = h.p.feedback.code_for(r.log_id)
    verified = h.p.feedback.verify("s1", r.log_id, code)
    h.clock.advance(7 * 86400); hlr_before = h.svc.hlr.calls
    tok2, _ = h.session(fingerprint=fp, age_hours=None)
    r2 = h.send(h.web_request(session=tok2))
    return dict(first_risk_score=round(r.risk_score, 2), verified=verified, return_risk_score=round(r2.risk_score, 2),
                hlr_lookups_on_return=h.svc.hlr.calls - hlr_before, channel=r2.channel,
                note="Real user verifies once; a week later they are trusted: lower score, no HLR spend.")


def scenario_circuit_breaker(backend):
    h = new_harness(backend); h.lift_source_caps(); h.cfg.global_sms_per_hour = 10
    modes = []
    for i in range(12):
        # spread numbers inside a known prefix so only the breaker acts (no pattern or prefix signals)
        r = h.send(h.web_request(ip=f"198.53.{i}.1", mobile=f"96650{(i * 7654321) % 10**7:07d}"))
        modes.append((h.p.mode, r.channel))
    young, _ = h.session(age_hours=0)
    risky = h.send(h.web_request(session=young, ip="198.53.99.1", mobile="966509999999"))
    return dict(hourly_budget=10, sms_sent=h.sms_sent, mode_after_each=[m for m, _ in modes],
                clean_user_in_emergency=modes[-1][1], risky_user_in_emergency=risky.channel,
                note="At 80 % the breaker goes elevated, at 100 % emergency: clean traffic (score < 10) still gets SMS, anything riskier is downgraded.")


SCENARIOS = [
    ("original_incident_single_client", lambda b: scenario_single_client_random_numbers(b)),
    ("datacenter_rotation_default_config", lambda b: scenario_datacenter_ip_rotation(b, False)),
    ("datacenter_rotation_caps_lifted", lambda b: scenario_datacenter_ip_rotation(b, True)),
    ("residential_rotation_feedback_loop", scenario_residential_rotation_feedback),
    ("sms_pumping_premium_prefix", scenario_sms_pumping),
    ("sequential_number_walk", scenario_sequential_walk),
    ("legitimate_user_journey", scenario_legitimate_user),
    ("global_circuit_breaker", scenario_circuit_breaker),
]


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--backend", default="memory", choices=["memory", "redis"])
    ap.add_argument("--out", default=str(ROOT / "results")); a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    results = {}
    for name, fn in SCENARIOS:
        results[name] = fn(a.backend)
        print(f"{name}: {json.dumps({k: v for k, v in results[name].items() if k != 'note'})}")
    (out / "scenarios.json").write_text(json.dumps({"backend": a.backend, "results": results}, indent=2) + "\n")
    lines = ["# Scenario results", "", f"Generated by `scripts/run_scenarios.py --backend {a.backend}`. Deterministic: seeded RNG, fake clock.", "",
             "| Scenario | Requests | SMS sent | Key outcome |", "|---|---:|---:|---|"]
    for name, r in results.items():
        extra = {k: v for k, v in r.items() if k not in ("requests", "sms_sent", "note")}
        lines.append(f"| `{name}` | {r.get('requests', '')} | {r.get('sms_sent', '')} | {json.dumps(extra) if extra else ''} |")
    lines += ["", "## Notes", ""] + [f"- **{n}**: {r['note']}" for n, r in results.items()]
    (out / "scenarios.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {out / 'scenarios.md'} and scenarios.json")


if __name__ == "__main__":
    main()
