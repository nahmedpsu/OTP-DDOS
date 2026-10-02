.PHONY: install test test-report scenarios analysis evaluation evaluation-quick load-test figures headline replay-demo pseudocode smoke results run-api run-worker clean

PY ?= python3

install:            ## dev install (editable) with test extras
	$(PY) -m pip install -e ".[dev,google]"

test:               ## run the full suite (memory and Redis backends)
	$(PY) -m pytest

test-report:        ## run the suite and record the output under results/
	$(PY) -m pytest -rA -o addopts="" -q 2>&1 | tee results/test_report.txt

scenarios:          ## run the attack scenarios and write results/scenarios.{md,json}
	$(PY) scripts/run_scenarios.py

analysis:           ## attacker profiles, false positives, v1 vs v2 cost, sensitivity -> results/analysis.{md,json}
	$(PY) scripts/run_analysis.py

evaluation:         ## 30-seed evaluation with CIs, ablation, sweeps, adaptive attackers -> results/evaluation.{md,json}, tradeoff.png
	$(PY) scripts/run_evaluation.py --seeds 30 --sweep-seeds 10

evaluation-quick:   ## 3-seed version of the above, for CI
	$(PY) scripts/run_evaluation.py --quick --out /tmp/otp-guard-eval

load-test:          ## pipeline and HTTP latency on a real Redis, KS timing-leak test, capacity -> results/performance.{md,json}
	$(PY) scripts/load_test.py

figures:            ## manuscript figures from the recorded results -> paper/figures/
	$(PY) paper/figures.py

headline:           ## provenance of every README number -> results/headline_numbers.md
	$(PY) scripts/headline_numbers.py

replay-demo:        ## generate synthetic logs in the replay schema and replay them under v1 and v2
	$(PY) scripts/generate_synthetic_logs.py --out /tmp/otp-guard-logs.csv --attacker datacenter_rotation
	$(PY) scripts/replay_logs.py --input /tmp/otp-guard-logs.csv

pseudocode:         ## regenerate docs/pseudocode/ from the design document
	$(PY) scripts/extract_pseudocode.py

smoke:              ## boot the HTTP service on fakes and drive a flow; writes results/api_smoke.txt
	$(PY) scripts/smoke_api.py

results: test-report scenarios analysis evaluation counter-study load-test smoke figures headline   ## regenerate everything under results/ and paper/figures/

counter-study:      ## the destination-counter study (config/counter_protocol.json) -> results/counter_study.*
	$(PY) scripts/run_counter_study.py

run-api:            ## run the HTTP service from the environment (.env)
	PYTHONPATH=src $(PY) -m otp_guard.api

run-worker:         ## run the background worker
	PYTHONPATH=src $(PY) -m otp_guard.worker

clean:
	rm -rf .pytest_cache build *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
