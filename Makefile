.PHONY: install test test-report scenarios pseudocode smoke results run-api run-worker clean

PY ?= python3

install:            ## dev install (editable) with test extras
	$(PY) -m pip install -e ".[dev,google]"

test:               ## run the full suite (memory and Redis backends)
	$(PY) -m pytest

test-report:        ## run the suite and record the output under results/
	$(PY) -m pytest -rA -o addopts="" -q 2>&1 | tee results/test_report.txt

scenarios:          ## run the attack scenarios and write results/scenarios.{md,json}
	$(PY) scripts/run_scenarios.py

pseudocode:         ## regenerate docs/pseudocode/ from the design document
	$(PY) scripts/extract_pseudocode.py

smoke:              ## boot the HTTP service on fakes and drive a flow; writes results/api_smoke.txt
	$(PY) scripts/smoke_api.py

results: test-report scenarios smoke   ## regenerate everything under results/

run-api:            ## run the HTTP service from the environment (.env)
	PYTHONPATH=src $(PY) -m otp_guard.api

run-worker:         ## run the background worker
	PYTHONPATH=src $(PY) -m otp_guard.worker

clean:
	rm -rf .pytest_cache build *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
