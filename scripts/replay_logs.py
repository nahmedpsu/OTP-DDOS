#!/usr/bin/env python3
"""Replay anonymised production logs through the pipeline under v1 and v2 and report the
metrics of docs/evaluation.md per label. Schema: docs/replay_schema.md.

    python3 scripts/replay_logs.py --input logs.csv [--features v1|v2] [--caps-lifted]

No production logs were available to the authors; scripts/generate_synthetic_logs.py writes a
file in the same schema from the calibrated simulation so the tool is exercised end to end.
"""
import argparse
import collections
import csv
import hashlib
import heapq
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.config import ALL_FEATURES, V1_FEATURES                          # noqa: E402
from otp_guard.evaluation.metrics import AttackMetrics, FrictionMetrics, containment   # noqa: E402
from otp_guard.evaluation.sim import cost_model                                    # noqa: E402
from otp_guard.services import IpInfo                                             # noqa: E402
from otp_guard.testing import Harness                                              # noqa: E402

REQUIRED = ["ts", "ip", "asn", "asn_type", "ip_country", "platform", "fingerprint", "session",
            "mobile_cc", "mobile_prefix", "mobile_hash", "recaptcha_score", "verified", "verify_delay_s"]


def synth_mobile(cc, prefix, mobile_hash):
    """Deterministic 12-digit number preserving country code and prefix; the rest comes from the hash."""
    tail = int(hashlib.sha256(mobile_hash.encode()).hexdigest(), 16) % 10 ** (12 - len(cc + prefix[len(cc):]))
    p = prefix if prefix.startswith(cc) else cc + prefix
    return (p + str(tail).zfill(12 - len(p)))[:12]


def replay(rows, features, cap_multiple=None, minute_bucket=60):
    """cap_multiple=None lifts the source caps (behavioural layers only); a number sets the per-minute
    web cap to that multiple of the median legitimate rows per minute, as the simulation does."""
    h = Harness()
    h.cfg.features = features
    h.cfg.response_floor_ms = 0
    h.cfg.asn_limit_default = 10 ** 9
    if cap_multiple is None:
        h.lift_source_caps()
    else:
        t0 = min(float(r["ts"]) for r in rows)
        per_min = collections.Counter(int((float(r["ts"]) - t0) // 60) for r in rows if r.get("label", "legit") != "attack")
        median = sorted(per_min.values())[len(per_min) // 2] if per_min else 1
        sl = h.cfg.source_limits["App/RegisterOTP"]
        sl["per_minute_web"] = max(1, int(cap_multiple * median)); sl["per_hour_web"] = sl["per_minute_web"] * 60
        sl["per_country"] = {}
    h.svc.prefixes.entries.clear()
    rows = sorted(rows, key=lambda r: float(r["ts"]))
    t_start = float(rows[0]["ts"])
    h.clock.t = t_start
    sessions, verif = {}, []
    per_min = collections.defaultdict(lambda: {"attack_req": 0, "attack_leaked": 0})
    friction = FrictionMetrics(); stopped = collections.Counter()
    hlr0, rc0 = h.svc.hlr.calls, h.svc.recaptcha.calls
    for i, row in enumerate(rows):
        ts = float(row["ts"])
        while verif and verif[0][0] <= ts:
            _, sid, log_id = heapq.heappop(verif)
            h.clock.t = max(h.clock.t, verif and verif[0][0] or h.clock.t)
            h.p.feedback.verify(sid, log_id, h.p.feedback.code_for(log_id))
        h.clock.t = ts
        h.p.feedback.run_due_timeouts()
        ip = row["ip"] if row["ip"].count(".") == 3 else None
        if ip is None:                                   # hashed: synthesise an address per subnet hash
            sub = int(hashlib.sha256(row.get("subnet_hash", row["ip"]).encode()).hexdigest(), 16) % (1 << 16)
            host = int(hashlib.sha256(row["ip"].encode()).hexdigest(), 16) % 254 + 1
            ip = f"100.{64 + (sub >> 8) % 64}.{sub & 255}.{host}"
        h.svc.ip_intel.by_ip[ip] = IpInfo(asn=row["asn"], asn_type=row["asn_type"], is_datacenter=row["asn_type"] == "hosting",
                                          is_proxy=row.get("is_proxy", "0") == "1", country=row["ip_country"],
                                          abuse_score=float(row.get("abuse_score", 0) or 0))
        if row.get("is_proxy", "0") == "1": h.svc.proxy.proxy_ips.add(ip)
        platform = row["platform"]
        sid = row["session"]
        if sid not in sessions:
            sessions[sid] = h.p.sessions.issue("legacy_app" if platform == "legacy_app" else platform, row["fingerprint"], 10 ** 9)
            if row.get("fp_first_seen"):
                h.p.sessions.set_first_seen(row["fingerprint"], float(row["fp_first_seen"]))
        prefix = row["mobile_prefix"]
        if prefix not in h.svc.prefixes.entries:
            h.svc.prefixes.add(prefix, row.get("prefix_class", "standard"), int(row.get("prefix_cost", 1) or 1))
        mobile = synth_mobile(row["mobile_cc"], prefix, row["mobile_hash"])
        if row.get("hlr_assigned", "1") == "0": h.svc.hlr.unassigned.add(mobile)
        tok = f"cap{i}"; h.svc.recaptcha.scores[tok] = float(row["recaptcha_score"] or 0)
        kw = dict(session=sessions[sid], ip=ip, mobile=mobile, recaptcha=tok, text="x" * int(row.get("text_len", 30) or 30))
        if platform in ("ios", "android"):
            req = h.app_request(platform, session=sessions[sid], ip=ip, mobile=mobile)
        elif platform == "legacy_app":
            req = h.legacy_app_request(session=sessions[sid], ip=ip, mobile=mobile)
        else:
            req = h.web_request(**kw)
        r = h.send(req)
        label = row.get("label", "unknown")
        m = per_min[int((ts - t_start) // minute_bucket)]
        if label == "attack":
            m["attack_req"] += 1
            stopped[r.rejected_at or f"sent:{r.channel}:{r.tier}"] += 1
            if r.channel == "sms": m["attack_leaked"] += 1
        else:
            friction.users += 1
            if r.tier == "challenge": friction.challenged += 1
            if r.channel is not None:
                friction.delivered += 1
                if r.tier == "delay": friction.delayed += 1; friction.added_delay_s_total += h.svc.sender.sent[-1].delay
            else:
                friction.refused += 1
        if r.channel == "sms" and row["verified"] == "1":
            heapq.heappush(verif, (ts + float(row["verify_delay_s"] or 30), h.p.sms_history[r.log_id]["session_id"], r.log_id))
    minutes = sorted(per_min)
    leaked = [per_min[m]["attack_leaked"] for m in minutes]
    reqs = [per_min[m]["attack_req"] for m in minutes]
    attack = AttackMetrics.build(leaked, reqs, h.svc.hlr.calls - hlr0, h.svc.recaptcha.calls - rc0, cost_model(), stopped) if minutes else None
    return {"rows": len(rows), "attack": attack.__dict__ if attack else None, "friction": friction.finish().__dict__}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--features", default="both", choices=["v1", "v2", "both"])
    ap.add_argument("--cap-multiple", type=float, default=None,
                    help="per-minute source cap as a multiple of the median legitimate rate; default lifts the caps")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    with open(a.input) as f:
        rows = list(csv.DictReader(f))
    missing = [c for c in REQUIRED if c not in rows[0]]
    if missing:
        sys.exit(f"missing columns: {missing}; see docs/replay_schema.md")
    out = {}
    for name, feats in (("v1", V1_FEATURES), ("v2", ALL_FEATURES)):
        if a.features in ("both", name):
            out[name] = replay(rows, feats, a.cap_multiple)
            at, fr = out[name]["attack"], out[name]["friction"]
            print(f"{name}: rows={out[name]['rows']} attack_leaked={at and at['leaked_total']} ttc={at and at['time_to_containment_min']} "
                  f"legit_delivered={fr['delivered_pct']:.1f}% challenged={fr['challenge_rate_pct']:.1f}% refused={fr['refusal_rate_pct']:.1f}%")
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(out, indent=1, default=str) + "\n")


if __name__ == "__main__":
    main()
