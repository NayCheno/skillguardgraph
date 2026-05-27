.PHONY: demo test smoke eval-main eval-all tables validate benchmark ecosystem triage reproduce clean scan trace

PYTHONPATH_OPT = PYTHONPATH=src

smoke:
	$(PYTHONPATH_OPT) python scripts/run_demo.py
	$(PYTHONPATH_OPT) python -m pytest tests/ -q

test:
	$(PYTHONPATH_OPT) python -m pytest tests/ -v

benchmark:
	$(PYTHONPATH_OPT) python scripts/build_benchmark.py

validate:
	$(PYTHONPATH_OPT) python scripts/validate_labels.py

eval-main:
	$(PYTHONPATH_OPT) python scripts/run_detector_eval.py
	$(PYTHONPATH_OPT) python scripts/run_ablation.py
	$(PYTHONPATH_OPT) python scripts/run_runtime_redteam.py

tables:
	$(PYTHONPATH_OPT) python scripts/make_tables.py

ecosystem:
	$(PYTHONPATH_OPT) python scripts/crawl_ecosystem.py

triage:
	$(PYTHONPATH_OPT) python scripts/triage_findings.py

eval-all: benchmark validate eval-main tables ecosystem triage

reproduce: benchmark validate eval-main tables

clean:
	rm -rf results/main/*.json results/main/tables.* results/ecosystem/*.json data/benchmark_v0 data/ecosystem

demo:
	$(PYTHONPATH_OPT) python scripts/run_demo.py

scan:
	$(PYTHONPATH_OPT) python -m skillguardgraph.cli scan-manifest examples/manifests/suspicious_scope_drift.json

trace:
	$(PYTHONPATH_OPT) python -m skillguardgraph.cli eval-trace examples/traces/split_exfil_chain.json
