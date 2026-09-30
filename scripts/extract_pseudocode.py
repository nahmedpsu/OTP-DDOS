#!/usr/bin/env python3
"""Extract every pseudocode block from docs/sms_validation_process.md into docs/pseudocode/,
one file per section, each with a pointer to the implementing function. Re-run after editing
the design so the two never drift:

    python3 scripts/extract_pseudocode.py
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "sms_validation_process.md"
OUT = ROOT / "docs" / "pseudocode"

IMPLEMENTATION = {
    "Atomic RateLimit": "src/otp_guard/store.py: LUA_TRY_ACQUIRE, LUA_TRY_ACQUIRE_ALL, RateLimit, MemoryStore.try_acquire*, RedisStore.try_acquire*",
    "Reputation Store": "src/otp_guard/reputation.py: ReputationStore.conversion_ratio",
    "Step 0": "src/otp_guard/pipeline.py: Pipeline.establish_trusted_platform, Pipeline.step0_connection_and_client_integrity",
    "Step 1": "src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService",
    "Step 2": "src/otp_guard/pipeline.py: Pipeline.step2_network_throttles",
    "Step 3": "src/otp_guard/pipeline.py: Pipeline.step3_recaptcha",
    "Step 4": "src/otp_guard/pipeline.py: Pipeline.step4_origin",
    "Step 5": "src/otp_guard/pipeline.py: Pipeline.step5_number, NumberTracker",
    "Step 6": "src/otp_guard/pipeline.py: Pipeline.step6_text",
    "Step 7": "src/otp_guard/pipeline.py: Pipeline.compute_risk_score, Pipeline.decide_tier, Pipeline.step7_risk",
    "Step 8": "src/otp_guard/pipeline.py: Pipeline.step8_per_number",
    "Step 9": "src/otp_guard/pipeline.py: Pipeline.effective_limit, Pipeline.step9_source_limits; src/otp_guard/reputation.py: AdaptiveLimits",
    "Step 10": "src/otp_guard/pipeline.py: Pipeline.step10_circuit_breaker",
    "Step 11": "src/otp_guard/pipeline.py: Pipeline.select_channel, Pipeline.step11_log_and_send",
    "Verification Feedback Loop": "src/otp_guard/feedback.py: FeedbackLoop",
    "Full Pipeline": "src/otp_guard/pipeline.py: Pipeline._process, Pipeline.process",
}


def impl_for(title):
    for key, val in IMPLEMENTATION.items():
        if title.startswith(key):
            return val
    return None


def main():
    text = DESIGN.read_text()
    sections = re.split(r"^(#{2,3} .+)$", text, flags=re.M)
    OUT.mkdir(exist_ok=True)
    for f in OUT.glob("*.md"):
        f.unlink()
    index = ["# Pseudocode", "", "Extracted from [`docs/sms_validation_process.md`](../sms_validation_process.md) by",
             "`scripts/extract_pseudocode.py`. Do not edit these files by hand; edit the design and re-run.", "",
             "| Section | File | Implemented in |", "|---|---|---|"]
    n = 0
    for i in range(1, len(sections), 2):
        title = sections[i].lstrip("# ").strip()
        body = sections[i + 1]
        blocks = re.findall(r"```(?:\w*)\n(.*?)```", body, flags=re.S)
        blocks = [b for b in blocks if not b.lstrip().startswith("{")]        # skip JSON examples
        if not blocks:
            continue
        n += 1
        slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
        fname = f"{n:02d}_{slug}.md"
        impl = impl_for(title)
        out = [f"# {title}", "", f"Source: `docs/sms_validation_process.md`, section \"{title}\".", ""]
        if impl:
            out += [f"Implemented in: `{impl}`", ""]
        for b in blocks:
            out += ["```", b.rstrip(), "```", ""]
        (OUT / fname).write_text("\n".join(out))
        index.append(f"| {title} | [`{fname}`]({fname}) | {('`' + impl + '`') if impl else ''} |")
    (OUT / "README.md").write_text("\n".join(index) + "\n")
    print(f"wrote {n} pseudocode files to {OUT}")


if __name__ == "__main__":
    main()
