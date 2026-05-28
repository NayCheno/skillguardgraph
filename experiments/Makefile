.PHONY: demo test smoke eval-main eval-all tables validate benchmark ecosystem triage reproduce clean scan trace latency real-ecosystem real-ecosystem-large real-ecosystem-xl real-ecosystem-5k real-ecosystem-10k significance generalization runtime-harness sandbox-harness third-party-sandbox

# Cross-platform PYTHONPATH setup
ifeq ($(OS),Windows_NT)
  PYTHONPATH_OPT = set "PYTHONPATH=src" &&
else
  PYTHONPATH_OPT = PYTHONPATH=src
endif

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
	$(PYTHONPATH_OPT) python scripts/run_runtime_harness.py
	$(PYTHONPATH_OPT) python scripts/run_latency.py
	$(PYTHONPATH_OPT) python scripts/run_sandbox_harness.py
	$(PYTHONPATH_OPT) python scripts/run_third_party_sandbox.py
	$(PYTHONPATH_OPT) python scripts/run_bootstrap_ci.py
	$(PYTHONPATH_OPT) python scripts/run_generalization_eval.py

tables:
	$(PYTHONPATH_OPT) python scripts/run_failure_analysis.py
	$(PYTHONPATH_OPT) python scripts/make_tables.py
	$(PYTHONPATH_OPT) python scripts/run_significance_tests.py

ecosystem:
	$(PYTHONPATH_OPT) python scripts/crawl_ecosystem.py

real-ecosystem:
	$(PYTHONPATH_OPT) python scripts/crawl_real_ecosystem.py --target 1000 --pages-per-query 3 --source-budget 100 --resume

real-ecosystem-large:
	$(PYTHONPATH_OPT) python scripts/crawl_real_ecosystem.py --target 2000 --pages-per-query 3 --source-budget 25 --sources github_mcp,npm_mcp,hf_spaces_mcp --output-prefix real_ecosystem_large --resume

real-ecosystem-xl:
	$(PYTHONPATH_OPT) python scripts/crawl_real_ecosystem.py --target 3000 --pages-per-query 3 --output-prefix real_ecosystem_xl --resume

real-ecosystem-5k:
	$(PYTHONPATH_OPT) python scripts/crawl_real_ecosystem.py --target 5000 --pages-per-query 6 --source-budget 25 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=2600,npm_mcp=2000,pypi_mcp=20,hf_spaces_mcp=380 --output-prefix real_ecosystem_5k --resume

real-ecosystem-10k:
	$(PYTHONPATH_OPT) python scripts/crawl_real_ecosystem.py --target 10000 --pages-per-query 10 --source-budget 0 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=4000,npm_mcp=4000,pypi_mcp=1620,hf_spaces_mcp=380 --output-prefix real_ecosystem_10k --resume

triage:
	$(PYTHONPATH_OPT) python scripts/triage_findings.py

significance:
	$(PYTHONPATH_OPT) python scripts/run_significance_tests.py

generalization:
	$(PYTHONPATH_OPT) python scripts/run_generalization_eval.py

runtime-harness:
	$(PYTHONPATH_OPT) python scripts/run_runtime_harness.py

third-party-sandbox:
	$(PYTHONPATH_OPT) python scripts/run_third_party_sandbox.py

sandbox-harness:
	$(PYTHONPATH_OPT) python scripts/run_sandbox_harness.py

latency:
	$(PYTHONPATH_OPT) python scripts/run_latency.py

eval-all: benchmark validate eval-main tables ecosystem triage real-ecosystem

reproduce: benchmark validate eval-main tables

clean:
ifeq ($(OS),Windows_NT)
	if exist results\main\*.json del /q results\main\*.json
	if exist results\main\tables.* del /q results\main\tables.*
	if exist results\ecosystem\*.json del /q results\ecosystem\*.json
	if exist data\benchmark_v0 rmdir /s /q data\benchmark_v0
	if exist data\ecosystem rmdir /s /q data\ecosystem
else
	rm -rf results/main/*.json results/main/tables.* results/ecosystem/*.json data/benchmark_v0 data/ecosystem
endif

demo:
	$(PYTHONPATH_OPT) python scripts/run_demo.py

scan:
	$(PYTHONPATH_OPT) python -m skillguardgraph.cli scan-manifest examples/manifests/suspicious_scope_drift.json

trace:
	$(PYTHONPATH_OPT) python -m skillguardgraph.cli eval-trace examples/traces/split_exfil_chain.json
