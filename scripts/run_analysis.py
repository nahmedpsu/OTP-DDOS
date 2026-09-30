#!/usr/bin/env python3
"""Quantitative analysis of the pipeline: attacker profiles against each layer, false-positive
risk for legitimate use cases, v1 versus v2 cost, and threshold sensitivity.
Deterministic (seeded RNG, fake clock, fakes for vendors). Writes results/analysis.{md,json}.

    python3 scripts/run_analysis.py [--sms-unit-cost 0.05]
"""
import argparse
import collections
import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.config import ALL_FEATURES, V1_FEATURES     # noqa: E402
from otp_guard.services import IpInfo                       # noqa: E402
from otp_guard.testing import Harness                       # noqa: E402

RESIDENTIAL = "100.64.0.0/10"
DATACENTER = "203.0.0.0/8"


def harness(features=ALL_FEATURES, caps_lifted=True, otp_ttl=600, denylist_min=50, cgnat=False):
    h = Harness()
    h.cfg.features = features
    h.cfg.otp_ttl = otp_ttl
    h.cfg.denylist_min_sample = denylist_min
    if caps_lifted:
        h.lift_source_caps()
        h.cfg.asn_limit_default = 100000
    h.svc.ip_intel.register(RESIDENTIAL, IpInfo(asn="AS9000", asn_type="isp", country="SA"))
    h.svc.ip_intel.register(DATACENTER, IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True, country="DE"))
    h.svc.ip_intel.register("198.18.0.0/15", IpInfo(asn="AS39386", asn_type="isp", country="SA"))   # a mobile carrier
    if cgnat:
        h.cfg.cgnat_asns = ("AS39386",)
    return h


def res_ip(k):
    """A residential pool spreads over the whole ISP range; hash k so consecutive requests land in different /24s."""
    x = (k * 2654435761) % (1 << 22)
    return f"100.{64 + (x >> 16)}.{(x >> 8) & 255}.{x & 255}"


def dc_ip(k):
    return f"203.{k % 256}.{(k * 13) % 256}.{(k * 7) % 250 + 1}"


# ---------------------------------------------------------------- attacker profiles
# each profile: (h, k, rng) -> Request

def p_naive(h, k, rng, state):
    if "tok" not in state:
        state["tok"], _ = h.session()
    return h.web_request(session=state["tok"], ip="198.51.100.10", mobile=f"9665{rng.randrange(10**8):08d}")


def p_datacenter(h, k, rng, state):
    return h.attacker_request(ip=dc_ip(k), mobile=f"9665{rng.randrange(10**8):08d}")


def p_residential_bot(h, k, rng, state):
    return h.attacker_request(ip=res_ip(k), mobile=f"9665{rng.randrange(10**8):08d}", recaptcha="mid")


def p_residential_farm(h, k, rng, state):
    return h.attacker_request(ip=res_ip(k), mobile=f"9665{rng.randrange(10**8):08d}", recaptcha="good")


def p_reused_profile(h, k, rng, state):
    if k % 3 == 0:                                      # new session every 3 requests (session cap)
        state["tok"], _ = h.session("web", fingerprint="real-browser-profile", age_hours=48)
    return h.web_request(session=state["tok"], ip=res_ip(k), mobile=f"9665{rng.randrange(10**8):08d}")


def p_sequential(h, k, rng, state):
    return h.attacker_request(ip=res_ip(k), mobile=f"966501{k:06d}")


def p_premium(h, k, rng, state):
    return h.attacker_request(ip=res_ip(k), mobile=f"96699{k:07d}")


def p_residential_aged_fps(h, k, rng, state):
    """Patient attacker: unique fingerprints seeded two hours earlier, good captcha, random numbers."""
    tok, _ = h.session("web", age_hours=2)
    return h.web_request(session=tok, ip=res_ip(k), mobile=f"9665{rng.randrange(10**8):08d}")


def p_spoofed_platform(h, k, rng, state):
    return h.attacker_request(ip=res_ip(k), mobile=f"9665{rng.randrange(10**8):08d}",
                              header_platform="ios", host="attacker.local")


ATTACKERS = [
    ("naive_single_client", "One IP, one session, random numbers", p_naive),
    ("datacenter_ip_rotation", "Fresh IP and fingerprint per request from a hosting ASN abroad", p_datacenter),
    ("residential_rotation_bot", "Residential proxy pool, fresh fingerprint, reCAPTCHA score 0.6", p_residential_bot),
    ("residential_captcha_farm", "Residential proxy pool, fresh fingerprint, reCAPTCHA score 0.9", p_residential_farm),
    ("residential_aged_unique_fingerprints", "Residential pool, unique fingerprints pre-aged 2 h, reCAPTCHA 0.9", p_residential_aged_fps),
    ("residential_reused_browser_profile", "Residential pool, one real 48-hour-old browser profile reused", p_reused_profile),
    ("sequential_numbers", "Residential pool, numbers 966501000000 upward", p_sequential),
    ("premium_prefix_pumping", "Residential pool, premium-rate prefix 96699", p_premium),
    ("spoofed_platform_header", "Residential pool, HTTP_PLATFORM: ios without attestation", p_spoofed_platform),
]


def run_attacker(profile, minutes=20, rate=30, **hkw):
    return run_attacker_in(harness(**hkw), profile, minutes, rate)


def run_attacker_in(h, profile, minutes=20, rate=30):
    rng, state = random.Random(7), {}
    per_minute, stops = [], collections.Counter()
    for m in range(minutes):
        before = h.sms_sent
        for i in range(rate):
            r = h.send(profile(h, m * rate + i, rng, state))
            stops[r.rejected_at or ("sent:" + (r.channel or "none") + ":" + (r.tier or ""))] += 1
        h.clock.advance(60)
        h.p.feedback.run_due_timeouts()
        per_minute.append(h.sms_sent - before)
    last = max([i for i, v in enumerate(per_minute) if v > 0], default=-1) + 1
    return {"requests": minutes * rate, "sms_sent": h.sms_sent, "per_minute": per_minute,
            "last_minute_with_sms": last, "sustained_rate_last_10_min": sum(per_minute[-10:]) / 10,
            "stopped_by": dict(stops.most_common())}


# ---------------------------------------------------------------- legitimate use cases

def verify_fraction(h, log_ids, fraction, rng):
    for lid in log_ids:
        if rng.random() < fraction:
            rec = h.p.sms_history[lid]
            h.p.feedback.verify(rec["session_id"], lid, h.p.feedback.code_for(lid))


def uc_normal_user(h, rng):
    tok, _ = h.session()
    r = h.send(h.web_request(session=tok, ip=res_ip(1)))
    return {"delivered": r.channel is not None, "tier": r.tier, "risk_score": r.risk_score}


def uc_retry_user(h, rng):
    tok, _ = h.session()
    r1 = h.send(h.web_request(session=tok, ip=res_ip(2)))
    h.clock.advance(70)
    r2 = h.send(h.web_request(session=tok, ip=res_ip(2)))
    h.clock.advance(20)
    r3 = h.send(h.web_request(session=tok, ip=res_ip(2)))
    return {"first": r1.channel, "retry_after_70s": r2.channel, "retry_after_20s_more": r2.channel and r3.rejected_at,
            "note": "second retry inside the 120 s backoff window is refused"}


def uc_campaign_burst(h, rng, users=200, minutes=5, verify=0.85):
    """New visitors from a campaign: unique residential IPs, fresh fingerprints, most verify."""
    tiers, delivered, log_ids = collections.Counter(), 0, []
    per_min = users // minutes
    for m in range(minutes):
        for i in range(per_min):
            k = m * per_min + i
            tok, _ = h.session("web", age_hours=0)
            r = h.send(h.web_request(session=tok, ip=res_ip(1000 + k), mobile=f"96650{(k * 7654321) % 10**7:07d}"))
            tiers[r.tier or r.rejected_at] += 1
            if r.channel:
                delivered += 1; log_ids.append(r.log_id)
        h.clock.advance(60)
        verify_fraction(h, log_ids[-per_min:], verify, rng)       # this minute's users verify
        h.p.feedback.run_due_timeouts()
    return {"users": users, "delivered": delivered, "delivered_pct": round(100 * delivered / users, 1),
            "tiers": dict(tiers)}


def uc_cgnat_office(h, rng, users=100, minutes=10):
    """Subscribers of one mobile carrier share a public IP; 10 sign up per minute behind it."""
    delivered, stops = 0, collections.Counter()
    for m in range(minutes):
        for i in range(users // minutes):
            k = m * 10 + i
            tok, _ = h.session("web", age_hours=3)
            r = h.send(h.web_request(session=tok, ip="198.18.5.5", mobile=f"96655{(k * 7654321) % 10**7:07d}"))
            stops[r.rejected_at or "sent"] += 1
            delivered += r.channel is not None
        h.clock.advance(60)
    return {"users": users, "delivered": delivered, "delivered_pct": round(100 * delivered / users, 1), "outcomes": dict(stops)}


def uc_vpn_user(h, rng):
    h.svc.proxy.proxy_ips.add(res_ip(3))
    r = h.send(h.web_request(ip=res_ip(3)))
    return {"http_status": r.http_status, "delivered": r.channel is not None, "note": "blocked by policy (Step 0)"}


def uc_corporate_datacenter_egress(h, rng):
    h.svc.ip_intel.register("192.0.2.0/24", IpInfo(asn="AS64501", asn_type="hosting", is_datacenter=True, country="SA"))
    r_mature = h.send(h.web_request(ip="192.0.2.10"))
    tok, _ = h.session("web", age_hours=0)
    r_new = h.send(h.web_request(session=tok, ip="192.0.2.11", mobile="966501234568"))
    return {"mature_browser": (r_mature.tier, r_mature.channel, r_mature.risk_score),
            "new_browser": (r_new.tier, r_new.channel, r_new.risk_score)}


def uc_legit_user_on_attacked_isp(h, rng):
    """A residential attack has been running for 20 minutes on this ISP; now a real customer signs up."""
    run_attacker_in(h, p_residential_aged_fps, minutes=20, rate=30)
    tok, _ = h.session()
    first = h.send(h.web_request(session=tok, ip="100.99.1.1", mobile="966509999999"))
    after = h.send(h.web_request(session=tok, ip="100.99.1.1", mobile="966509999999", challenge_proof="challenge-ok"))
    return {"first_response": first.body.get("status"), "first_tier": first.tier, "first_score": first.risk_score,
            "after_challenge": (after.tier, after.channel), "isp_denylisted": h.p.store.exists("deny:asn:AS9000"),
            "note": "one interactive challenge, then delivered; the ISP is never denylisted"}


def uc_roaming_user(h, rng):
    h.svc.ip_intel.register("198.51.200.0/24", IpInfo(asn="AS5384", asn_type="isp", country="AE"))
    r = h.send(h.web_request(ip="198.51.200.7"))
    return {"tier": r.tier, "risk_score": r.risk_score, "delivered": r.channel is not None}


def uc_legacy_app_user(h, rng):
    r = h.send(h.legacy_app_request())
    return {"tier": r.tier, "delivered": r.channel is not None}


def uc_returning_trusted_user(h, rng):
    tok, fp = h.session()
    r = h.send(h.web_request(session=tok, ip=res_ip(4)))
    h.p.feedback.verify("s1", r.log_id, h.p.feedback.code_for(r.log_id))
    h.clock.advance(30 * 86400)
    tok2, _ = h.session(fingerprint=fp, age_hours=None)
    r2 = h.send(h.web_request(session=tok2, ip=res_ip(5)))
    return {"risk_score": r2.risk_score, "hlr_lookups": h.svc.hlr.calls, "delivered": r2.channel is not None}


USE_CASES = [
    ("normal_user", "One request, verifies", uc_normal_user, {}),
    ("retry_user", "Did not receive the SMS, retries", uc_retry_user, {}),
    ("campaign_burst_default_caps", "200 new visitors in 5 min, default source caps (web 5/min)", uc_campaign_burst, {"caps_lifted": False}),
    ("campaign_burst_caps_lifted", "200 new visitors in 5 min, caps lifted for the campaign", uc_campaign_burst, {"caps_lifted": True}),
    ("cgnat_carrier_default", "100 subscribers behind one carrier IP, 10/min (caps lifted to isolate the IP cap)", uc_cgnat_office, {"cgnat": False, "caps_lifted": True}),
    ("cgnat_carrier_listed", "Same, with the carrier ASN listed in CGNAT_ASNS", uc_cgnat_office, {"cgnat": True, "caps_lifted": True}),
    ("vpn_user", "Legitimate user on a VPN", uc_vpn_user, {}),
    ("corporate_datacenter_egress", "Office traffic leaving through a hosting ASN in-country", uc_corporate_datacenter_egress, {}),
    ("roaming_user", "Saudi number, connecting from the UAE", uc_roaming_user, {}),
    ("legacy_app_user", "App version without attestation, inside the grace window", uc_legacy_app_user, {}),
    ("returning_trusted_user", "Verified a month ago, comes back", uc_returning_trusted_user, {}),
    ("legit_user_on_attacked_isp", "Real customer of an ISP that has hosted a 20-minute flood (caps lifted)", uc_legit_user_on_attacked_isp, {"caps_lifted": True}),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sms-unit-cost", type=float, default=0.05, help="assumed cost per SMS in USD for the cost table")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    R = {"assumptions": {"attack_rate_per_minute": 30, "attack_minutes": 20, "sms_unit_cost_usd": a.sms_unit_cost,
                         "source_caps": "lifted to campaign scale in attacker runs (the blunt cap would otherwise hide every other layer)",
                         "prefix_table": "the sample table covers a few ranges only, so random numbers mostly land on 'unknown' prefixes (+10); "
                                         "a complete table would route them to HLR, which here answers 'assigned' for every number (generous to the attacker)"}}

    # A. attackers vs layers (v2, caps lifted)
    R["attackers"] = {}
    for name, desc, fn in ATTACKERS:
        R["attackers"][name] = dict(description=desc, **run_attacker(fn))
        print("attacker", name, R["attackers"][name]["sms_sent"])

    # B. legitimate use cases (default config unless the case says otherwise)
    R["use_cases"] = {}
    for name, desc, fn, hkw in USE_CASES:
        hk = {"caps_lifted": False}; hk.update(hkw)
        h = harness(**hk); rng = random.Random(11)
        R["use_cases"][name] = dict(description=desc, **fn(h, rng))
        print("use case", name, {k: v for k, v in R["use_cases"][name].items() if k != "description"})

    # C. v1 vs v2 cost at campaign-scale caps
    R["v1_vs_v2"] = {}
    for name, desc, fn in ATTACKERS:
        v1 = run_attacker(fn, features=V1_FEATURES)
        v2 = R["attackers"][name]
        R["v1_vs_v2"][name] = {"v1_sms": v1["sms_sent"], "v2_sms": v2["sms_sent"],
                               "v1_sustained_per_hour": round(v1["sustained_rate_last_10_min"] * 60),
                               "v2_sustained_per_hour": round(v2["sustained_rate_last_10_min"] * 60),
                               "v1_cost_20min_usd": round(v1["sms_sent"] * a.sms_unit_cost, 2),
                               "v2_cost_20min_usd": round(v2["sms_sent"] * a.sms_unit_cost, 2)}
        print("v1 vs v2", name, R["v1_vs_v2"][name]["v1_sms"], R["v1_vs_v2"][name]["v2_sms"])

    # D. sensitivity: OTP timeout and denylist sample against the hardest attacker, and campaign delivery
    R["sensitivity"] = []
    for ttl in (120, 300, 600):
        for dmin in (20, 50, 100):
            atk = run_attacker(p_residential_farm, otp_ttl=ttl, denylist_min=dmin)
            h = harness(caps_lifted=True, otp_ttl=ttl, denylist_min=dmin)
            camp = uc_campaign_burst(h, random.Random(11))
            R["sensitivity"].append({"otp_ttl_s": ttl, "denylist_min_sample": dmin, "attacker_sms_20min": atk["sms_sent"],
                                     "attacker_last_minute_with_sms": atk["last_minute_with_sms"],
                                     "campaign_delivered_pct": camp["delivered_pct"]})
            print("sensitivity", ttl, dmin, atk["sms_sent"], camp["delivered_pct"])

    (out / "analysis.json").write_text(json.dumps(R, indent=2) + "\n")
    write_markdown(R, out / "analysis.md")
    print("wrote", out / "analysis.md")


def write_markdown(R, path):
    L = ["# Analysis", "", f"Generated by `scripts/run_analysis.py`. Deterministic. Assumptions: {json.dumps(R['assumptions'])}", ""]
    L += ["## A. Attacker profiles against the v2 pipeline", "",
          "Each attacker sends 30 requests a minute for 20 minutes (600 requests) with every source cap lifted, so the",
          "table shows what the *other* layers do. `stopped_by` counts where each request ended.", "",
          "| Attacker | SMS sent / 600 | Last minute with any SMS | Sustained rate after detection (per min) | Stopped by |",
          "|---|---:|---:|---:|---|"]
    for n, r in R["attackers"].items():
        top = ", ".join(f"{k} {v}" for k, v in list(r["stopped_by"].items())[:3])
        L.append(f"| `{n}`<br>{r['description']} | {r['sms_sent']} | {r['last_minute_with_sms']} | {r['sustained_rate_last_10_min']:.1f} | {top} |")
    L += ["", "## B. Legitimate use cases (false-positive check)", "",
          "Default configuration unless the case says otherwise.", "",
          "| Use case | Outcome |", "|---|---|"]
    for n, r in R["use_cases"].items():
        body = {k: v for k, v in r.items() if k != "description"}
        L.append(f"| `{n}`<br>{r['description']} | `{json.dumps(body)}` |")
    L += ["", "## C. v1 versus v2 under the same attack, source caps lifted to campaign scale", "",
          f"Cost column assumes {R['assumptions']['sms_unit_cost_usd']} USD per SMS; change with `--sms-unit-cost`.", "",
          "| Attacker | v1 SMS / 20 min | v2 SMS / 20 min | v1 sustained per hour | v2 sustained per hour | v1 cost | v2 cost |",
          "|---|---:|---:|---:|---:|---:|---:|"]
    for n, r in R["v1_vs_v2"].items():
        L.append(f"| `{n}` | {r['v1_sms']} | {r['v2_sms']} | {r['v1_sustained_per_hour']} | {r['v2_sustained_per_hour']} | ${r['v1_cost_20min_usd']} | ${r['v2_cost_20min_usd']} |")
    L += ["", "## D. Sensitivity: OTP timeout and denylist sample size", "",
          "Hardest attacker (`residential_captcha_farm`) versus campaign delivery, both with caps lifted.", "",
          "| OTP timeout (s) | Denylist min resolved | Attacker SMS / 20 min | Attacker stopped after minute | Campaign delivered % |",
          "|---:|---:|---:|---:|---:|"]
    for s in R["sensitivity"]:
        L.append(f"| {s['otp_ttl_s']} | {s['denylist_min_sample']} | {s['attacker_sms_20min']} | {s['attacker_last_minute_with_sms']} | {s['campaign_delivered_pct']} |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
