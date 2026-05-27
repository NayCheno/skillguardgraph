# Last Smoke Test

Executed in this environment before packaging:

```bash
cd experiments
PYTHONPATH=src python scripts/run_demo.py
PYTHONPATH=src python scripts/run_ablation_stub.py
PYTHONPATH=src python -m pytest -q
```

Result:

```text
4 passed
```
