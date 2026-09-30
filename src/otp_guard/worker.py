"""Background tick: resolve OTP timeouts (feeds the feedback loop) and run the adaptive
baseline job. Run one of these per deployment: `python -m otp_guard.worker`."""
import logging
import time

log = logging.getLogger("otp_guard.worker")


def tick(pipeline, baseline_source=None):
    pipeline.feedback.run_due_timeouts()
    if baseline_source is not None:
        # baseline_source yields (source, platform, cc, observed, expected_median, mad, conversion)
        for row in baseline_source():
            pipeline.adaptive.recompute(*row)


def run_forever(pipeline, interval=60, baseline_source=None):
    while True:
        try:
            tick(pipeline, baseline_source)
        except Exception as e:  # keep the loop alive
            log.exception("worker tick failed: %s", e)
        time.sleep(interval)


def main():
    from .factory import build_pipeline
    logging.basicConfig(level=logging.INFO)
    p, _ = build_pipeline()
    run_forever(p)


if __name__ == "__main__":
    main()
