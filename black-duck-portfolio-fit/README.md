# Black Duck Portfolio Fit — `tool_fit` Scoring

Per-company, per-product fit scoring for the Black Duck application-security
portfolio. This folder is self-contained and unrelated to the rest of the
repository.

## How scoring works

For each company we score fit **0–100 against each product independently**, then
take the **weighted max** to pick a recommended **lead product**. The default
lead is **Black Duck SCA/SBOM** (the universal, broadest wedge) unless a stronger
**Defensics** (protocol/safety) or **Coverity** (large embedded codebase) signal
dominates.

| Product | Secures | Strongest fit signal | Mandate hook |
|---|---|---|---|
| **Black Duck (SCA + SBOM)** | OSS/third-party component & license risk, SBOM | Anyone shipping code built on OSS (universal) | CRA, EO 14028/NTIA, hyperscaler contracts |
| **Coverity (SAST) + LLM/AI-SAST** | Source-level defects/vulns in C/C++/app code | Large in-house codebase; AI/ML or AI-codegen code | ISO 21434, SSDF static analysis |
| **DAST** | Running web/app/API attack surface | Companion apps, cloud/OTA, management portals | CRA connected-service security, OWASP |
| **Defensics (fuzzing)** | Protocol/file/interface robustness | Comms stacks (5G/Wi-Fi/BT, CAN/Ethernet), OT protocols, safety interfaces | R155/21434, IEC 62443 |

## Inputs

> **Note:** No company list was provided with the task (no input file, GitHub
> issue, or PR). The set below is a **representative archetype sample drawn from
> the rubric** to demonstrate the scoring and lead-selection logic. Replace it
> with a real list to regenerate. Machine-readable output: [`tool_fit.json`](./tool_fit.json).

## Results

| Company | Archetype | Black Duck | Coverity | DAST | Defensics | **Lead** |
|---|---|:--:|:--:|:--:|:--:|---|
| MediaTek | Connectivity SoC / firmware | 88 | 85 | 30 | **95** | Defensics |
| ASUS | Consumer device + apps/cloud | **85** | 65 | 80 | 70 | Black Duck |
| Bosch Mobility | Automotive Tier-1 / ADAS | 85 | 90 | 45 | **92** | Defensics |
| Supermicro | Server / BMC builder | **90** | 78 | 70 | 65 | Black Duck |
| Advantech | Industrial / edge IoT | **88** | 70 | 60 | 82 | Black Duck |
| Robotics/SLAM vendor | Autonomy stack + AI codegen | 85 | **88** | 35 | 68 | Coverity + LLM-SAST |

### One-line wedges

- **MediaTek** — Fuzz the 5G/Wi-Fi/BT stacks you ship before a carrier or CRA assessor does.
- **ASUS** — SBOM-first across the device fleet, DAST attach for the app/cloud/OTA ecosystem.
- **Bosch Mobility** — Bus/interface fuzzing to evidence R155/21434 robustness; Coverity attach on the safety codebase.
- **Supermicro** — SBOM as the contract-gate opener for hyperscaler/federal deals; Coverity attach on BMC/BIOS.
- **Advantech** — SBOM for IEC 62443/CRA market access; Defensics attach on the OT protocol stacks.
- **Robotics/SLAM vendor** — LLM-assisted SAST on the AI-generated C++ autonomy code; Black Duck attach for the ROS/OSS tree.

## Reading the logic

The default lead is Black Duck because SBOM is the universal, lowest-friction
wedge — every Phase 2/5 company ships code built on OSS and SBOM is an explicit
deliverable under CRA / EO 14028 / hyperscaler contracts. Defensics overtakes it
only where the company **authors** comms/protocol or safety-critical interface
stacks (MediaTek, Bosch), since fuzz/robustness is the differentiated, high-value
wedge that R155/21434 and IEC 62443 explicitly expect. Coverity (with LLM-SAST
weighted up) overtakes where a **large in-house C/C++ or AI-generated codebase**
shipped externally dominates the risk (the robotics/SLAM autonomy vendor).
