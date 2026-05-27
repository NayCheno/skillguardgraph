.PHONY: demo test scan trace ablation

demo:
	PYTHONPATH=src python scripts/run_demo.py

test:
	PYTHONPATH=src python -m pytest -q

scan:
	PYTHONPATH=src python -m skillguardgraph.cli scan-manifest examples/manifests/suspicious_scope_drift.json

trace:
	PYTHONPATH=src python -m skillguardgraph.cli eval-trace examples/traces/cross_skill_flow.json

ablation:
	PYTHONPATH=src python scripts/run_ablation_stub.py
