## AI Justification for CapScan

### Purpose
CapScan augments `nmap`-based network scanning with AI to accelerate analysis, reduce noise, and provide clear, actionable remediation guidance. AI is used for interpretation only; raw evidence remains the source of truth.

### Where AI Fits in CapScan
- Interpreting `python-nmap` outputs and NSE/script data
- Summarizing findings in the `ttkbootstrap` GUI (flatly theme)
- Generating mitigation recommendations via `tgpt`
- Prioritizing/triaging issues while preserving raw evidence in `sqlcipher3`

### Benefits
- **Accelerated triage**: Converts raw scan output into prioritized, human-readable insights in seconds per host.
- **Actionable remediation**: Produces service- and CVE-aware fixes and compensating controls.
- **Noise reduction**: Groups duplicates, de-emphasizes low-signal checks, highlights exploitability by service exposure/version.
- **Consistency**: Standardizes severity rationales and remediation language across analysts and scans.
- **Bridging skill gaps**: Junior analysts get expert-style narratives without deep CVE/protocol expertise.
- **Evidence preservation**: Recommendations are derived views; raw encrypted data is preserved in `sqlcipher3` for audit.
- **Cost-effectiveness**: Automates routine analysis that would otherwise require senior engineer time.
- **Adaptability**: Incorporates contextual signals (asset criticality, exposure) without rewriting parsers.

### Safety, Quality, and Governance
- **Grounding**: Prompts include exact banners, service versions, CVE IDs, and relevant script outputs. Reject unverifiable claims.
- **Determinism controls**: AI outputs are tagged with prompt/model metadata and linked to source artifacts.
- **Human-in-the-loop**: Treat AI output as draft. Analyst approval is required before ticketing or auto-remediation.
- **Data security**: Scan data at rest is encrypted with `sqlcipher3`. Avoid sensitive payloads in prompts; anonymize host details.
- **Versioning**: Store model/prompt versions with each AI summary to ensure reproducibility.
- **Auditability**: Keep raw `nmap` outputs and NSE results; recommendations must reference the specific evidence used.

### When Not to Rely on AI
- Novel zero-days or issues lacking public context
- Regulatory reports that require citation-backed, strictly deterministic language
- Environments where outbound prompt data is disallowed (use fully local models or disable AI)

### Measurement (Benchmarkable Value)
Track the following to validate ROI:
- Time-to-triage per host/service
- Duplicate/derivative finding rate
- False-positive/negative delta vs. baseline scripts/tools
- Mean time to remediation (MTTR) from ticket creation to closure
- Analyst satisfaction and variance in write-ups

### Implementation Notes
- Engine: `python-nmap` as scanning core; AI only interprets outputs.
- GUI: `ttkbootstrap` summaries and next steps are AI-generated, labeled as such.
- Storage: Raw and parsed data in `sqlcipher3`; AI summaries stored as derived artifacts with provenance.
- Reasoning: `tgpt` for mitigation recommendations and risk articulation. Prompts are grounded and minimal.

### Operational Guardrails
- Label AI-generated text in the UI and reports.
- Provide one-click access from any AI claim to the exact raw evidence.
- Enforce prompt templates that require citations to the underlying artifacts.
- Maintain a kill-switch to disable AI features globally.

### Summary
Using AI in CapScan is justified because it speeds triage, improves remediation quality, and scales consistent analysis—while preserving raw, auditable evidence and enforcing human review and strict governance.


