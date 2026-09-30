import csv
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_synthetic_logs_replay_round_trip(tmp_path):
    out = tmp_path / "logs.csv"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_synthetic_logs.py"), "--out", str(out),
                    "--attacker", "datacenter_rotation", "--minutes", "8", "--attack-start-minute", "3"], check=True)
    rows = list(csv.DictReader(open(out)))
    assert {r["label"] for r in rows} == {"legit", "attack"}
    sys.path.insert(0, str(ROOT / "scripts"))
    import replay_logs
    from otp_guard.config import ALL_FEATURES, V1_FEATURES
    v1 = replay_logs.replay(rows, V1_FEATURES)
    v2 = replay_logs.replay(rows, ALL_FEATURES)
    assert v1["attack"]["leaked_total"] > 0
    assert v2["attack"]["leaked_total"] == 0 and v2["attack"]["time_to_containment_min"] == 0
    assert v2["friction"]["delivered_pct"] > 95
