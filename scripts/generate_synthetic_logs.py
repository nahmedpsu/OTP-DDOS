#!/usr/bin/env python3
"""Write a CSV in the replay schema (docs/replay_schema.md) from the calibrated distributions:
legitimate traffic plus one attacker profile. Exists so scripts/replay_logs.py can be run end to
end before real logs are available.

    python3 scripts/generate_synthetic_logs.py --out logs.csv [--attacker residential_captcha_farm] [--minutes 30]
"""
import argparse
import csv
import hashlib
import math
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.evaluation.runner import ATTACKERS                       # noqa: E402
from otp_guard.evaluation.sim import LegitSpec, STANDARD_PREFIXES, ELEVATED_PREFIX, PREMIUM_PREFIX   # noqa: E402
from otp_guard.evaluation.calibration import value as cal               # noqa: E402

COLUMNS = ["ts", "ip", "subnet_hash", "asn", "asn_type", "ip_country", "is_proxy", "platform", "attested", "fingerprint",
           "fp_first_seen", "session", "mobile_cc", "mobile_prefix", "prefix_class", "prefix_cost", "mobile_hash",
           "recaptcha_score", "text_len", "hlr_assigned", "verified", "verify_delay_s", "label"]


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--attacker", default="residential_captcha_farm", choices=list(ATTACKERS))
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--attack-start-minute", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    legit, atk = LegitSpec(), ATTACKERS[a.attacker]
    t0 = 1_700_000_000
    rows = []
    for minute in range(a.minutes):
        for _ in range(rng.randrange(int(legit.rate_per_min * 0.7), int(legit.rate_per_min * 1.3) + 1)):
            ts = t0 + minute * 60 + rng.random() * 60
            fresh = rng.random() < legit.fresh_fp_fraction
            fp = h(f"legit-fp-{rng.randrange(10**7)}")
            ver = rng.random() < legit.conversion
            rows.append(dict(ts=f"{ts:.3f}", ip=f"100.{64 + rng.randrange(64)}.{rng.randrange(256)}.{rng.randrange(1, 255)}",
                             subnet_hash="", asn="AS9000", asn_type="isp", ip_country="SA", is_proxy=0, platform="web", attested=0,
                             fingerprint=fp, fp_first_seen=f"{ts if fresh else ts - 86400:.0f}", session=h(f"s{ts}{fp}"),
                             mobile_cc="966", mobile_prefix=rng.choice(STANDARD_PREFIXES), prefix_class="standard", prefix_cost=1,
                             mobile_hash=h(f"legit-num-{rng.randrange(10**7)}"), recaptcha_score=f"{rng.betavariate(*legit.captcha_beta):.2f}",
                             text_len=30, hlr_assigned=1, verified=int(ver),
                             verify_delay_s=f"{legit.verify_median_s * math.exp(rng.gauss(0, legit.verify_sigma)):.1f}" if ver else "",
                             label="legit"))
        if minute >= a.attack_start_minute:
            for k in range(int(atk.rate_per_min)):
                ts = t0 + minute * 60 + rng.random() * 60
                idx = rng.randrange(atk.pool_size)
                fp = h(f"atk-fp-{rng.randrange(10**9)}") if atk.fp_mode in ("fresh", "aged") else h("atk-profile")
                prefix = {"premium": PREMIUM_PREFIX, "elevated": ELEVATED_PREFIX}.get(atk.numbers, rng.choice(STANDARD_PREFIXES))
                cls = {"premium": "premium", "elevated": "elevated"}.get(atk.numbers, "standard")
                rows.append(dict(ts=f"{ts:.3f}",
                                 ip=("198.51.100.10" if atk.network == "single_ip" else
                                     f"203.{idx % 256}.{(idx * 13) % 256}.{(idx * 7) % 250 + 1}" if atk.network == "datacenter" else
                                     f"100.{64 + (idx >> 12) % 64}.{(idx >> 4) & 255}.{idx % 254 + 1}"),
                                 subnet_hash="", asn="AS64500" if atk.network == "datacenter" else "AS9000",
                                 asn_type="hosting" if atk.network == "datacenter" else "isp",
                                 ip_country=atk.ip_country, is_proxy=0, platform="web", attested=0, fingerprint=fp,
                                 fp_first_seen=f"{ts - (7200 if atk.fp_mode == 'aged' else 0):.0f}", session=h(f"as{ts}{k}"),
                                 mobile_cc="966", mobile_prefix=prefix, prefix_class=cls, prefix_cost={"premium": 12, "elevated": 3}.get(cls, 1),
                                 mobile_hash=h(f"atk-num-{minute}-{k}") if atk.numbers != "sequential" else h(f"seq-{minute * 60 + k}"),
                                 recaptcha_score=f"{rng.betavariate(*atk.captcha_beta):.2f}", text_len=30, hlr_assigned=1,
                                 verified=int(rng.random() < atk.verify_fraction), verify_delay_s=f"{atk.verify_delay_s:.1f}", label="attack"))
    rows.sort(key=lambda r: float(r["ts"]))
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS); w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows to {a.out}")


if __name__ == "__main__":
    main()
