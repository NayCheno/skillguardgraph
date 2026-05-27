# SkillGuardGraph Ethics Protocol

This document establishes the ethical constraints, data handling policies, and responsible disclosure procedures governing the SkillGuardGraph research project. All members of the research team must read and comply with this protocol before conducting experiments, collecting data, or preparing artifacts for release.

---

## 1. Guiding Principles

1. **Do no harm.** The research must not create tools, datasets, or knowledge that can be directly used to attack real systems or real users.
2. **Transparency.** The methods, limitations, and ethical constraints of the research must be clearly documented in the paper, artifact, and any public-facing materials.
3. **Proportionality.** The intrusiveness of measurement and testing must be proportional to the research objectives. Passive analysis is preferred over active probing; synthetic data is preferred over real data.
4. **Responsible disclosure.** If real vulnerabilities are discovered during ecosystem measurement, they must be reported to affected parties before publication.

---

## 2. Synthetic Data Policy

### 2.1 Attack Samples

All malicious skill samples in the benchmark are constructed synthetically. The following rules apply without exception:

- **Fake credentials:** All API keys, tokens, OAuth secrets, passwords, and authentication artifacts used in attack samples are randomly generated and do not correspond to any real service account. Example: `sk-test-fake-000000000000000000000000` for OpenAI-style keys; `AKIAFAKE000000000000` for AWS-style keys.
- **Sinkhole domains:** All network endpoints referenced in attack samples (e.g., exfiltration destinations, callback URLs) resolve to locally controlled sinkhole infrastructure or use reserved domains (e.g., `*.example.com`, `*.test`, `*.invalid` as defined by RFC 6761 and RFC 2606). No sample contacts a real third-party service.
- **Synthetic enterprise data:** All "sensitive" data objects (documents, emails, database records, credentials) used in attack scenarios are fabricated. They may resemble real data formats (e.g., a synthetic invoice, a fake employee record) but contain no real PII, financial data, or proprietary information.
- **Synthetic organization profiles:** Enterprise environments referenced in attack scenarios (company names, department structures, user identities) are entirely fictional.

### 2.2 Benign Samples

Benign samples in the benchmark are sourced from:

1. **Official examples and documentation:** Tool definitions and MCP server implementations published as examples by protocol authors and platform vendors.
2. **Open-source projects:** Publicly available MCP servers, LangChain tools, and similar open-source agent components, used in compliance with their respective licenses.
3. **Synthetic benign skills:** Fabricated but realistic tool definitions that mimic enterprise connectors, used when real examples are insufficient to achieve corpus size targets.

No benign sample is modified to include malicious behavior. Malicious variants are constructed as separate samples with distinct identifiers.

---

## 3. No Operational Payloads

### 3.1 Publication Constraint

The published paper, artifact, and supplementary materials must never include directly usable attack payloads against real systems. Specifically:

- **No real API exploitation code.** If an attack scenario involves calling a real API (e.g., a cloud service, a SaaS platform), the published code uses mock endpoints only.
- **No real credential stuffing.** Attack scenarios that involve credential abuse use synthetic credentials that map to sandbox or mock environments.
- **No real data exfiltration paths.** Network destinations in published attack code point to sinkhole infrastructure controlled by the research team or to reserved/example domains.
- **No detailed exploitation chains for unpatched vulnerabilities.** If a real vulnerability is discovered and disclosed (see Section 6), the paper reports the vulnerability at the class and pattern level only, with specifics deferred until the vendor has had reasonable time to patch.

### 3.2 De-Weaponization Process

Before artifact release, all attack samples undergo a de-weaponization review:

1. Each sample is reviewed to verify that no real credentials, real endpoints, real PII, or real organizational data are present.
2. Network calls are verified to target only sinkhole/mock infrastructure.
3. Any code that could be trivially modified to target a real system is annotated with a warning and accompanied by rate-limiting or sandbox-only execution guards.
4. The de-weaponization review is documented in the artifact's `SECURITY_ETHICS.md` file with reviewer sign-off.

---

## 4. Sandbox Isolation

### 4.1 Dynamic Probing Policy

All dynamic analysis (sandbox probing, red-team task execution, runtime monitoring experiments) is conducted exclusively against isolated environments:

- **Container isolation:** Sandbox probing runs in ephemeral containers with no access to the host network, filesystem, or credentials.
- **Mock services:** External API calls made by skills under test are intercepted by mock service infrastructure that simulates responses without contacting real third-party services.
- **Network sinkholes:** DNS and HTTP traffic from sandbox environments is routed to sinkhole servers that log requests and return controlled responses. No traffic reaches real external services.
- **No real third-party service calls.** At no point during development, testing, or evaluation does the system make uncontrolled calls to real third-party APIs, SaaS platforms, or cloud services on behalf of attack samples.

### 4.2 Sandbox Configuration Audit

The sandbox configuration (network rules, mount points, resource limits, mock service endpoints) is version-controlled and reviewed before each experiment run. The configuration is published as part of the artifact to enable reproduction.

### 4.3 Ecosystem Measurement Constraints

When measuring real-world open-source skills (RQ5), the following constraints apply:

- **Static analysis only for most samples.** The majority of ecosystem samples are analyzed via metadata scanning and source-code analysis only, without execution.
- **Selective dynamic analysis.** Only a curated subset of high-risk samples undergoes sandbox probing, and only within the isolation environment described above.
- **Rate limiting.** Any passive collection (e.g., fetching public repository metadata) respects rate limits and terms of service of the hosting platform.
- **No destructive operations.** No sample is executed in a way that modifies real external state (e.g., creating accounts, sending emails, writing to cloud storage).

---

## 5. Responsible Disclosure

### 5.1 Triggering Conditions

Responsible disclosure is triggered when ecosystem measurement reveals a finding that:

1. Affects a real, deployed system or service (not a toy example or abandoned project), AND
2. Could enable unauthorized access, data leakage, or other security harm if exploited, AND
3. Is not already publicly documented as a known vulnerability.

### 5.2 Disclosure Process

| Step | Action | Timeline |
|---|---|---|
| 1. Triage | Research team confirms the finding is a genuine vulnerability (not a false positive or intended behavior). | Within 1 week of discovery |
| 2. Vendor notification | Contact the maintainer or vendor via their published security contact (security@ email, HackerOne, or equivalent). Provide: description, affected component, reproduction steps, potential impact, and suggested mitigation. | Within 2 weeks of triage |
| 3. Embargo period | Allow the vendor 90 days to develop and release a fix. During this period, the finding is not disclosed publicly, discussed at conferences, or shared beyond the research team and the vendor. | 90 days from notification |
| 4. Follow-up | If no response is received within 2 weeks, re-send via alternative channels (e.g., GitHub security advisory, platform-specific vulnerability reporting). If still no response after 60 days, consider limited disclosure to a CERT/CC or equivalent coordinating body. | Ongoing |
| 5. Publication | After the embargo period expires (or the vendor releases a fix, whichever is earlier), the finding may be included in the paper at the class and pattern level. Specific details are included only to the extent necessary to support the research claims. | At or after embargo expiry |

### 5.3 Paper Treatment of Disclosed Vulnerabilities

- The paper reports the vulnerability at the **pattern level** (e.g., "We discovered N instances of scope inflation in the MCP ecosystem where tool declarations requested write access despite advertising read-only functionality").
- Specific repository URLs, package names, or vendor names are included only if: (a) the vulnerability has been patched, (b) the vendor has consented to disclosure, or (c) the information is already publicly available.
- The responsible disclosure timeline and outcome are documented in the paper's ethics section.

---

## 6. Benchmark Release Policy

### 6.1 Release Tiers

The benchmark is released in tiers with increasing access requirements:

| Tier | Contents | Access |
|---|---|---|
| **Public** | Benign samples, de-weaponized malicious samples, label schema, evidence path format, evaluation scripts, and expected outputs. | Freely available via the project repository. |
| **Controlled** | Full malicious sample set including samples with more realistic (but still synthetic) attack patterns. | Available upon request to researchers who agree to a responsible-use agreement. The agreement prohibits use for offensive purposes and requires that any derived datasets maintain the same ethical constraints. |
| **Internal** | Sandbox configurations, mock service implementations, sinkhole infrastructure details, and raw ecosystem measurement data. | Available only to the research team and artifact reviewers under NDA-equivalent terms. |

### 6.2 De-Weaponization Requirements

All publicly released malicious samples must satisfy:

1. No real credentials or tokens.
2. No real external service endpoints.
3. No real PII or proprietary data.
4. No directly executable exploit chains against real systems without modification.
5. Clear labeling as synthetic research artifacts.
6. An accompanying README explaining that the samples are for defensive research and must not be used for offensive purposes.

### 6.3 License and Terms

The benchmark is released under a research-use-only license that:

- Permits academic reproduction, extension, and comparison.
- Prohibits use for developing, testing, or deploying offensive tools.
- Requires that derived datasets maintain the same ethical constraints.
- Disclaims liability for misuse.

---

## 7. IRB Considerations

### 7.1 Applicability

This research does not involve human subjects in the traditional sense (no surveys, interviews, medical data, or behavioral experiments with human participants). Therefore, Institutional Review Board (IRB) approval is not required for the core research activities.

### 7.2 Exception: Alert Triage Time Measurement

The Alert Triage Time (ATT) metric (Section 5.2 of `metrics.md`) involves security analysts performing timed exercises with the system's output. If this evaluation involves participants who are not members of the research team:

- An IRB exemption or approval will be sought before conducting the evaluation.
- Participants will provide informed consent.
- No personally identifiable information will be collected from participants.
- Participants may withdraw at any time without consequence.
- Results will be reported in aggregate only.

### 7.3 Ecosystem Measurement and Public Data

Ecosystem measurement involves analyzing publicly available open-source code and metadata. This activity:

- Does not involve collecting data from private systems or non-public sources.
- Does not involve interacting with human subjects (developers of analyzed projects are not study participants).
- Respects the terms of service of hosting platforms (e.g., GitHub API rate limits).
- Does not attempt to deanonymize or identify individual developers.

---

## 8. Data Retention and Deletion Policy

### 8.1 Data Categories and Retention

| Data Category | Retention Period | Deletion Policy |
|---|---|---|
| Benchmark dataset (synthetic) | Permanent | Published as part of the artifact; no deletion required. |
| Ecosystem measurement raw data (public repos) | Duration of research project + 2 years | Deleted after retention period. Aggregated statistics may be retained permanently. |
| Sandbox execution logs | Duration of research project + 1 year | Logs contain only synthetic data interactions; deleted after retention period. |
| Real vulnerability findings | Until 1 year after disclosure resolution | Detailed reproduction steps are deleted after the vendor confirms a fix. Pattern-level descriptions are retained in the paper. |
| Mock service logs | Duration of research project | Deleted when the project concludes. |
| Participant data (if ATT study conducted) | Until publication + 1 year | Anonymized at collection; deleted after retention period. |

### 8.2 Secure Storage

- All research data is stored on encrypted storage (full-disk encryption or equivalent).
- Access is restricted to members of the research team.
- Real vulnerability findings are stored separately from the benchmark dataset and are not included in any public release.
- Credentials and infrastructure details for sinkhole/mock services are stored in a secrets manager and are not committed to version control.

### 8.3 Deletion Verification

Upon reaching the end of the retention period, data deletion is verified by a second team member and documented in the project's internal records.

---

## 9. Alignment with ACM Artifact Review and Badging

This section maps the ethics protocol to the requirements of the ACM Artifact Review and Badging v1.1 framework (https://www.acm.org/publications/policies/artifact-review-and-badging-current).

### 9.1 Artifact Documentation

The artifact package includes:

- **README.md:** Overview, setup instructions, and quick-start guide.
- **EXPERIMENTAL_SETUP.md:** Hardware, software, and configuration requirements.
- **EXPECTED_OUTPUTS.md:** Expected outputs for each experiment command, with tolerance ranges.
- **SECURITY_ETHICS.md:** This ethics protocol, adapted for artifact reviewers.
- **DATA_CARD.md:** Dataset provenance, labeling methodology, known limitations, and ethical constraints.

### 9.2 Artifact Functional Requirements

| ACM Criterion | How the Artifact Satisfies It |
|---|---|
| **Documented** | All scripts, configurations, and data formats are documented. The `make help` target lists all available commands. |
| **Consistent** | All claims in the paper are traceable to specific experiments. The `make tables` command regenerates all paper tables from raw results. |
| **Complete** | The artifact includes all code, data, and configurations needed to reproduce the main results. External dependencies are pinned via lock files. |
| **Exercisable** | `make smoke` completes in ≤ 10 minutes on commodity hardware and verifies that the system is functional. `make reproduce-main` reproduces the main paper results. |

### 9.3 Artifact Reusable Requirements (Strong Target)

Beyond functional requirements, the artifact aims for reusability:

- **Modular design:** Individual components (metadata analyzer, static analyzer, sandbox prober, runtime monitor, fusion engine) can be used independently.
- **Extensible schema:** The evidence graph schema and constraint library are designed for extension with new node types, edge types, and constraints.
- **Version pinning:** All dependencies are pinned to exact versions. The artifact includes a Dockerfile for one-command environment setup.
- **Test suite:** `make test` runs the full test suite with ≥ 90% code coverage on core modules.

### 9.4 No-Harm Guarantee for Artifact Reviewers

The artifact is designed so that artifact reviewers can evaluate it without risk:

- All experiments use synthetic data and mock services.
- No network traffic leaves the reviewer's machine (except optional package installation from standard repositories).
- Sandbox experiments run in containers with no host access.
- The artifact does not install persistent services, modify system configuration, or require elevated privileges (except for optional Docker usage).

---

## 10. Ethical Review Checklist

Before paper submission, the following checklist must be completed:

- [ ] All attack samples use fake credentials, sinkhole domains, and synthetic data.
- [ ] No published artifact contains real API keys, tokens, or credentials.
- [ ] No published artifact contains directly usable exploit code against real systems.
- [ ] All dynamic experiments were conducted in sandboxed environments.
- [ ] No real third-party services were called during attack testing.
- [ ] Ecosystem measurement respected platform terms of service and rate limits.
- [ ] All real vulnerability findings have been disclosed to affected vendors.
- [ ] The embargo period has expired (or vendor has confirmed fixes) for any disclosed vulnerabilities included in the paper.
- [ ] The benchmark release license prohibits offensive use.
- [ ] Data retention and deletion policies are documented and enforceable.
- [ ] The paper's ethics section accurately describes all ethical constraints and decisions.
- [ ] IRB approval or exemption has been obtained if human participants are involved in the ATT study.
- [ ] The artifact includes a `SECURITY_ETHICS.md` file summarizing these constraints for reviewers.
- [ ] A second team member has reviewed the de-weaponization of all publicly released attack samples.
