# Security and Ethics — SkillGuardGraph Artifact

This document describes the security constraints, ethical safeguards, and
compliance measures governing the SkillGuardGraph artifact. It is intended
for artifact reviewers, program committees, and researchers reproducing or
extending this work.

---

## 1. Data Safety

**All data in this artifact is synthetic.** No real credentials, PII,
proprietary enterprise data, or production configuration appears anywhere
in the benchmark, examples, or experiment outputs.

| Category | Safeguard |
|---|---|
| API keys & tokens | Randomly generated strings matching format conventions (e.g., `sk-test-fake-000000000000000000000000`, `AKIAFAKE000000000000`). None correspond to real service accounts. |
| Network endpoints | Reserved domains only: `*.example.invalid`, `*.sinkhole.test`, `*.test`, `127.0.0.1` per RFC 6761 and RFC 2606. No real third-party URLs. |
| Enterprise data | Fabricated documents, records, and credentials that resemble real formats but contain no real PII, financial data, or proprietary information. |
| Organization profiles | Entirely fictional company names, department structures, and user identities. |
| User information | No real user data collected, stored, or referenced. All usernames, emails, and identity attributes are synthetic. |

Benign samples are sourced from official protocol documentation, public
open-source examples (used under their respective licenses), and synthetic
skill definitions. No benign sample is modified to include malicious
behavior — malicious variants are distinct samples with separate identifiers.

---

## 2. Network Safety

**No experiment in this artifact contacts real external services.** All
experiments run entirely offline on the reviewer's local machine.

- **Sinkhole domains.** Every URL, callback endpoint, and exfiltration
  destination in the benchmark resolves to sinkhole infrastructure or
  reserved domains (`*.sinkhole.test`, `*.example.invalid`). DNS and HTTP
  traffic from sandbox environments is routed to controlled sinks that log
  requests and return canned responses.
- **No outbound traffic.** Dynamic analysis runs in ephemeral containers
  with no host network access. The sandbox configuration (network rules,
  mount points, resource limits) is published as
  `experiments/configs/sandbox.yaml`.
- **Sandbox prober uses pattern analysis.** The sandbox analyzer inspects
  metadata, declared permissions, and structural patterns in skill
  manifests. It does not invoke real API calls or execute skills against
  live services.
- **Mock service infrastructure.** Any code path that simulates external
  API interaction uses local mock endpoints that return controlled
  responses without contacting real third-party services.

Artifact reviewers do not need network access beyond optional `pip install`
from standard repositories.

---

## 3. Attack Sample Handling

All malicious samples in the 4,010-sample benchmark (3,010 malicious across 7
attack classes and 1,000 benign samples) use **de-weaponized patterns** designed for detection
research, not exploitation.

### 3.1 De-weaponization

- **No operational payloads.** Attack samples demonstrate detection
  signatures (scope inflation, capability laundering, consent laundering,
  confused deputy, delayed rug-pull, persistence pivot, split exfiltration)
  without containing functional exploit code against real systems.
- **Pattern-level representation.** Samples encode the structural and
  behavioral patterns that our analyzers detect, not end-to-end attack
  chains.
- **Publication constraint.** The public artifact omits specific exploit
  details for patterns that could be trivially adapted to real targets. The
  full sample set (including more realistic but still synthetic patterns) is
  available under a controlled-access responsible-use agreement.

### 3.2 Review process

Before release, every attack sample was reviewed to verify:

1. No real credentials, tokens, or API keys are present.
2. No real external service endpoints are referenced.
3. No real PII or proprietary data is included.
4. No directly executable exploit chains against real systems exist without
   modification.

---

## 4. Responsible Disclosure

### 4.1 Triggering conditions

Disclosure is triggered when ecosystem measurement (RQ5) reveals a finding
that: (a) affects a real, deployed system or service, (b) could enable
unauthorized access, data leakage, or other security harm, and (c) is not
already publicly documented.

### 4.2 Disclosure timeline

| Step | Action | Timeline |
|---|---|---|
| Triage | Confirm the finding is a genuine vulnerability | Within 1 week |
| Vendor notification | Contact maintainer via published security contact | Within 2 weeks of triage |
| Embargo | Vendor develops and releases a fix | 90 days from notification |
| Follow-up | Re-send via alternative channels if no response | 2 weeks, then 60 days |
| Publication | Report at pattern level after embargo or vendor confirmation | At or after embargo expiry |

### 4.3 Ecosystem measurement

The ecosystem measurement (1200 synthetic samples from 5 sources) uses a
**synthetic corpus simulation** methodology. Samples are constructed from
public metadata patterns, not scraped or copied wholesale from live
registries. No destructive operations are performed against real systems.

If real vulnerabilities were discovered during development or evaluation of
this research, they would be reported to affected maintainers before
publication. The paper reports findings at the pattern and class level,
deferring specifics until vendors have had reasonable time to address them.

---

## 5. Reproducibility vs. Safety

The artifact is designed to be **fully reproducible** while maintaining all
safety constraints.

| Property | Implementation |
|---|---|
| Deterministic results | All experiments use a fixed random seed (`42`). Outputs are bitwise reproducible across runs and platforms. |
| Fixed corpus | The 4,010-sample benchmark and 1,200-sample synthetic ecosystem corpus are generated deterministically. Re-running `make benchmark` and `make ecosystem` produces identical datasets. |
| No real-world data | Real-world data is not included in the public artifact. The ecosystem corpus simulates real-world patterns from 5 source categories (GitHub MCP, npm, HuggingFace, enterprise catalog, community forum) using synthetic samples. |
| Self-contained | All code, data, configurations, and expected outputs are included. No external datasets, APIs, or services are required to reproduce any result. |
| Expected outputs | `EXPECTED_OUTPUTS.md` documents every output file, its format, size, and the key metrics it contains — enabling bit-level verification. |

---

## 6. Compliance

### 6.1 ACM Artifact Review and Badging

This artifact targets the **Functional** badge under the ACM Artifact
Review and Badging v1.1 guidelines
(https://www.acm.org/publications/policies/artifact-review-and-badging-current).

| ACM Criterion | How This Artifact Satisfies It |
|---|---|
| **Documented** | All scripts, configurations, and data formats are documented. `make help` lists all available targets. |
| **Consistent** | Every claim in the paper traces to a specific experiment. `make tables` regenerates all paper tables from raw results. |
| **Complete** | All code, data, and configurations needed to reproduce the main results are included. Dependencies are minimal (Python 3.10+ stdlib + pytest). |
| **Exercisable** | `make smoke` completes in ≤ 10 minutes and verifies the system is functional. `make reproduce` reproduces all primary results. |

### 6.2 No-Harm Guarantee

The artifact is safe for artifact reviewers to evaluate:

- All experiments use synthetic data and mock services.
- No network traffic leaves the reviewer's machine (except optional package
  installation).
- Sandbox experiments run in containers with no host filesystem or network
  access.
- The artifact does not install persistent services, modify system
  configuration, or require elevated privileges.
- No real third-party API calls are made during any experiment run.

### 6.3 Licensing

The benchmark and code are released under a research-use-only license:

- Permits academic reproduction, extension, and comparison.
- Prohibits use for developing, testing, or deploying offensive tools.
- Requires that derived datasets maintain the same ethical constraints.
- Disclaims liability for misuse.

---

## 7. References

- Full ethics protocol: `docs/ethics_protocol.md`
- Policy specification: `docs/policy_spec.md`
- Benchmark data card: `docs/benchmark_card.md`
- Metrics definitions: `docs/metrics.md`
- Sandbox configuration: `experiments/configs/sandbox.yaml`
- Policy rules: `experiments/configs/policy.yaml`
