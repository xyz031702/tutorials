# Black Duck Portfolio Fit — `tool_fit` Scoring

Per-company, per-product fit scoring for the Black Duck application-security
portfolio. This folder is self-contained and unrelated to the rest of the
repository.

## Hard criteria (mandatory gates)

Applied **before** any scoring — a company must pass **every** gate to be scored.

| Gate | Rule |
|---|---|
| **HQ in Taiwan** | Global corporate HQ legally domiciled in Taiwan (not just a Taiwan-born founder or a regional office). |
| **Well-established** | Publicly listed (TWSE/TPEx) or clear market leader, founded ≥ ~15 years ago, sustained revenue at scale. Excludes startups. |

**Excluded by the gates** (shown for traceability): Bosch Mobility (HQ Germany),
Supermicro (HQ USA), and any early-stage robotics/SLAM startup (not established).

## How scoring works

For each surviving company we score fit **0–100 against each product
independently**, then take the **weighted max** to pick a recommended **lead
product**. The default lead is **Black Duck SCA/SBOM** (the universal, broadest
wedge) unless a stronger **Defensics** (protocol/safety) or **Coverity** (large
embedded codebase) signal dominates.

| Product | Secures | Strongest fit signal | Mandate hook |
|---|---|---|---|
| **Black Duck (SCA + SBOM)** | OSS/third-party component & license risk, SBOM | Anyone shipping code built on OSS (universal) | CRA, EO 14028/NTIA, hyperscaler contracts |
| **Coverity (SAST) + LLM/AI-SAST** | Source-level defects/vulns in C/C++/app code | Large in-house codebase; AI/ML or AI-codegen code | ISO 21434, SSDF static analysis |
| **DAST** | Running web/app/API attack surface | Companion apps, cloud/OTA, management portals | CRA connected-service security, OWASP |
| **Defensics (fuzzing)** | Protocol/file/interface robustness | Comms stacks (5G/Wi-Fi/BT, Ethernet), OT protocols, safety interfaces | R155/21434, IEC 62443 |

## Inputs

> **Note:** No company list was provided with the task. The set below is a
> representative sample of **well-established, Taiwan-HQ** companies selected to
> satisfy the hard criteria and exercise the scoring/lead logic. Replace with a
> real list to regenerate. Machine-readable output: [`tool_fit.json`](./tool_fit.json).

## Results (Taiwan-HQ, well-established)

| Company | HQ | Founded | Archetype | Black Duck | Coverity | DAST | Defensics | **Lead** |
|---|---|:--:|---|:--:|:--:|:--:|:--:|---|
| MediaTek | Hsinchu | 1997 | Connectivity SoC / firmware | 88 | 85 | 30 | **95** | Defensics |
| ASUS | Taipei | 1989 | Consumer device + apps/cloud | **85** | 65 | 80 | 70 | Black Duck |
| Advantech | Taipei | 1983 | Industrial / edge IoT | **88** | 70 | 60 | 82 | Black Duck |
| Realtek | Hsinchu | 1987 | Networking/connectivity SoC | 84 | 83 | 25 | **90** | Defensics |
| Quanta Computer | Taoyuan | 1988 | Server / notebook ODM | **92** | 75 | 68 | 66 | Black Duck |
| Synology | New Taipei | 2000 | NAS + DSM web OS | 86 | 68 | **88** | 60 | Black Duck |
| Moxa | New Taipei | 1987 | Industrial networking / OT | 84 | 70 | 55 | **88** | Defensics |

### One-line wedges

- **MediaTek** — Fuzz the 5G/Wi-Fi/BT stacks you ship before a carrier or CRA assessor does.
- **ASUS** — SBOM-first across the device fleet, DAST attach for the app/cloud/OTA ecosystem.
- **Advantech** — SBOM for IEC 62443/CRA market access; Defensics attach on the OT protocol stacks.
- **Realtek** — Fuzz the Ethernet/Wi-Fi/BT/USB stacks baked into your silicon; Coverity attach on driver code.
- **Quanta Computer** — SBOM as the contract-gate opener for hyperscaler/federal server deals; Coverity attach on BMC/BIOS.
- **Synology** — SBOM across the DSM OSS base, with a strong DAST attach for the internet-facing DSM web/app surface.
- **Moxa** — Fuzz the OT protocol stacks that *are* your product (IEC 62443 robustness); Black Duck attach for SBOM.

## Reading the logic

Black Duck is the default lead because SBOM is the universal, lowest-friction
wedge — every Phase 2/5 company ships code built on OSS and SBOM is an explicit
deliverable under CRA / EO 14028 / hyperscaler / IEC 62443 contracts. Defensics
overtakes it where the company **authors** comms/protocol stacks (MediaTek,
Realtek) or OT protocols (Moxa), since fuzz/robustness is the differentiated,
high-value wedge that R155/21434 and IEC 62443 explicitly expect. DAST surges as
a strong attach (not lead) where there is a large internet-facing app surface
(Synology DSM, ASUS app/cloud).
