# Responsible Disclosure Log Template

## 1. When to Disclose

A vulnerability in a skill, tool, connector, or MCP server warrants responsible disclosure when **all** of the following criteria are met:

1. **Confirmed exploitable**: The vulnerability has been demonstrated in a controlled environment, not merely hypothesized. Evidence includes a reproducible proof-of-concept showing the specific cross-layer trust violation.
2. **Material impact**: The vulnerability could result in unauthorized data access, credential theft, persistent manipulation of agent behavior, or silent exfiltration of sensitive information.
3. **Not already public**: The vulnerability has not been published, discussed in public forums, or independently discovered and disclosed by another party.
4. **Affects real users**: The vulnerable skill is deployed in production environments, available in public registries, or distributed through enterprise catalogs.
5. **Downstream risk**: The vulnerability is exploitable through normal agent workflows without requiring the user to perform unusual or obviously suspicious actions.

### Non-Disclosure Scenarios

The following do **not** warrant responsible disclosure:
- Theoretical vulnerabilities without a working proof-of-concept
- Vulnerabilities in deprecated or unpublished skills
- Issues that are purely cosmetic or have no security impact
- General weaknesses in the MCP specification itself (report to the specification maintainers separately)
- Vulnerabilities in the agent platform's runtime sandbox (report to the platform vendor)

## 2. Disclosure Process

### Step 1: Identify and Validate

1. Confirm the vulnerability through reproducible testing
2. Classify the attack class using the SkillGuardGraph taxonomy (T1–T7)
3. Assess severity using the cross-layer constraint framework:
   - **CRITICAL**: Sensitive data reaches external sink (C3), or capability laundering with active exfiltration
   - **HIGH**: Scope inflation with write access (C1/C7), untrusted-to-high-privilege chain (C2), persistence pivot (C6)
   - **MEDIUM**: Missing governance controls (no signature, untrusted publisher) combined with moderate capability
   - **LOW**: Minor metadata inconsistencies without demonstrated exploitability
4. Document the evidence path: which layers are involved, what evidence exists at each layer

### Step 2: Document

Prepare a complete vulnerability report (see Section 4 below) containing:
- Technical description of the vulnerability
- Affected skill/tool identity and version
- Attack class and severity classification
- Reproduction steps with proof-of-concept
- Evidence graph showing the cross-layer trust violation
- Recommended remediation

### Step 3: Contact Vendor/Publisher

1. Identify the responsible party:
   - **Registry operator** (npm, HuggingFace, GitHub Marketplace) for platform-level response
   - **Skill publisher** for code-level remediation
   - **Both** when the vulnerability spans platform governance and implementation
2. Send the initial disclosure notice (see Section 5 below)
3. Use encrypted communication when available (PGP key, Signal, secure email)
4. Confirm receipt within 5 business days

### Step 4: Embargo Period

- **Standard embargo**: 90 calendar days from initial contact
- **Critical actively exploited**: 7 calendar days (expedited disclosure)
- **Platform-level issue affecting multiple skills**: 30 calendar days
- The embargo begins on the date the vendor confirms receipt of the disclosure
- If no receipt confirmation within 14 days, attempt contact through alternative channels
- If no response within 30 days, proceed to publication

### Step 5: Publish

After the embargo period expires:
1. Publish the vulnerability report with coordinated disclosure
2. Credit the vendor's response and remediation (if applicable)
3. Update the SkillGuardGraph benchmark with the new sample
4. Notify relevant registry operators for catalog-level action

## 3. Embargo Period Details

### 90-Day Timeline

| Day | Action |
|---|---|
| 0 | Initial disclosure sent to vendor |
| 5 | Confirm receipt; if no response, escalate |
| 14 | If no receipt, attempt alternative contact channels |
| 30 | If no response, notify registry operator; prepare publication |
| 30–60 | Vendor develops and tests fix |
| 60 | Status check with vendor; confirm fix timeline |
| 75 | Pre-release notification to vendor; draft publication shared for accuracy review |
| 85 | Final review period closes |
| 90 | Publication of vulnerability report |

### Embargo Extensions

The embargo may be extended by up to 30 additional days if:
- The vendor provides a credible fix timeline with intermediate milestones
- The fix requires coordinated release across multiple parties
- Active exploitation has not been observed

Extensions require explicit agreement from both parties and are documented in the disclosure log.

### Embargo Violations

If the vulnerability is independently published or actively exploited during the embargo:
1. Immediately notify the vendor
2. Publish the complete disclosure within 24 hours
3. Update all registry operators

## 4. Disclosure Report Contents

### Required Sections

1. **Executive Summary**: One-paragraph description of the vulnerability and its impact
2. **Affected Component**: Skill name, version, publisher, registry, and discovery source
3. **Attack Classification**:
   - Primary attack class (T1–T7)
   - Lifecycle stages involved
   - Cross-layer evidence path
4. **Technical Description**:
   - What the skill declares (metadata layer)
   - What the skill implements (code layer)
   - What permissions it requests (permission layer)
   - What runtime behavior it exhibits (if observed)
   - Where the cross-layer trust violation occurs
5. **Severity Assessment**:
   - SkillGuardGraph constraint(s) triggered (C1–C7)
   - Severity level (LOW/MEDIUM/HIGH/CRITICAL)
   - CVSS-like impact assessment
6. **Proof of Concept**:
   - Minimal reproduction steps
   - Evidence graph visualization (or textual description)
   - Policy engine output showing the finding
7. **Recommended Remediation**:
   - For the skill publisher (code-level fix)
   - For the registry operator (catalog-level action)
   - For the agent platform (defense-in-depth measures)
8. **Timeline**: Key dates (discovery, contact, response, fix, publication)
9. **Credits**: Researcher attribution and acknowledgments

## 5. Vendor Communication Template

```
Subject: [CONFIDENTIAL] Security Vulnerability in [Skill Name] v[Version]

Dear [Vendor Name / Security Team],

I am writing to report a security vulnerability in [Skill Name] ([registry/package identifier]), discovered during a systematic security analysis of the MCP/agent skill ecosystem.

**Summary**: [One-sentence description of the vulnerability]

**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]

**Attack Class**: [T1–T7 classification]

**Impact**: [Brief description of what an attacker could achieve]

**Affected Versions**: [Version range]

This vulnerability exploits a cross-layer trust gap: the skill's [metadata/permissions/approval text] claims [benign behavior], but its [implementation/runtime behavior/persistence pattern] performs [malicious operation]. This is invisible to [single-layer defense] but detectable through cross-layer evidence fusion.

I have prepared a detailed vulnerability report with reproduction steps and a proof-of-concept. I am prepared to share this report under the following conditions:

1. **Embargo period**: 90 days from your acknowledgment of this notice
2. **Coordination**: I will work with you on timing for public disclosure
3. **Credit**: I request acknowledgment in any advisory or changelog

Please confirm receipt of this notice within 5 business days and designate a point of contact for ongoing coordination.

If I do not receive acknowledgment within 14 days, I will attempt to reach you through alternative channels. If no response is received within 30 days, I will proceed with public disclosure to protect users.

[Optional: PGP key fingerprint for encrypted communication]

Respectfully,
[Researcher Name]
[Affiliation]
[Contact Information]
```

## 6. Publication Template

```markdown
# [CVE-ID if assigned]: [Vulnerability Title]

**Published**: [Date]
**Discovered**: [Date]
**Vendor notified**: [Date]
**Vendor response**: [Date]
**Fix available**: [Date or "Not yet"]

## Summary

[Two-sentence summary of the vulnerability and its impact.]

## Affected Component

- **Skill**: [Name] v[Version]
- **Publisher**: [Publisher name]
- **Registry**: [npm/GitHub/HuggingFace/etc.]
- **Discovery source**: [How the skill was found]

## Technical Analysis

### Attack Classification

| Property | Value |
|---|---|
| Primary attack class | [T1–T7] |
| Lifecycle stages | [Discovery, Implementation, Invocation, ...] |
| SkillGuardGraph constraints | [C1, C3, ...] |
| Severity | [CRITICAL/HIGH/MEDIUM/LOW] |

### Cross-Layer Evidence Path

[Describe the evidence at each layer and how they compose:]

1. **Metadata layer**: [What the manifest declares]
2. **Implementation layer**: [What the code does]
3. **Permission layer**: [What scopes are requested]
4. **[Other layers as applicable]**

### Proof of Concept

[Step-by-step reproduction instructions]

### Evidence Graph

[Textual or visual representation of the evidence graph showing the trust violation path]

## Remediation

### For Skill Publishers
- [Specific code-level remediation steps]

### For Registry Operators
- [Catalog-level actions: flag, suspend, require signature]

### For Agent Platforms
- [Defense-in-depth measures: scope enforcement, runtime probing]

## Timeline

| Date | Event |
|---|---|
| [Date] | Vulnerability discovered |
| [Date] | Vendor notified |
| [Date] | Vendor confirmed receipt |
| [Date] | Fix released |
| [Date] | Publication |

## Credits

[Researcher names and affiliations]

## References

- SkillGuardGraph: [link to project]
- MCP Specification: https://spec.modelcontextprotocol.io
```

## 7. Ethics Review Requirements

### 7.1 Institutional Review

All ecosystem measurement activities involving real-world skill analysis must be reviewed by the researchers' Institutional Review Board (IRB) or equivalent ethics committee before:
- Crawling public registries
- Analyzing skills with real user data
- Contacting vendors about vulnerabilities

### 7.2 Ethical Constraints

The following constraints apply to all measurement and disclosure activities:

1. **No active exploitation**: Never execute malicious skill behavior against real systems or users. All analysis must be performed in isolated environments.
2. **No user data collection**: Do not collect, store, or process user data from skill executions. Analysis is limited to manifests, source code, and metadata.
3. **No registry abuse**: Do not publish malicious skills, spam registries, or create accounts for research purposes without registry operator consent.
4. **Proportional disclosure**: Match disclosure urgency to severity. Do not embargo low-severity issues for the full 90 days if the fix is trivial. Do not delay critical disclosures for bureaucratic reasons.
5. **No attribution without consent**: Do not identify skill publishers, developers, or users in publications without their consent. Use anonymized identifiers.
6. **Dual-use awareness**: Recognize that the benchmark and attack taxonomy developed for defense can also be used for offense. Limit public release of exploit-grade proof-of-concept code.

### 7.3 Data Handling

- Synthetic corpus data may be published without restriction
- Real-world sample data must be anonymized before publication
- Vulnerability details must follow the embargo schedule before publication
- All data must be stored in accordance with institutional data management policies

### 7.4 IRB Protocol Summary

| Item | Description |
|---|---|
| Study type | Security measurement / vulnerability analysis |
| Data sources | Public registries, open-source repositories |
| Human subjects | None (analysis of software artifacts) |
| Risk level | Minimal (no user interaction, no data collection) |
| Consent | Not applicable (publicly available software) |
| Benefits | Improved security for LLM agent ecosystems |
| Publication | Anonymized findings, embargo-responsible disclosure |
