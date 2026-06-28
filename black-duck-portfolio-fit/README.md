# Black Duck Portfolio Fit — `tool_fit` Scoring

Per-company, per-product fit scoring for the Black Duck application-security
portfolio. This folder is self-contained and unrelated to the rest of the
repository.

## Run it

```bash
python3 score_tool_fit.py     # writes tool_fit.json + prints a ranked table
```

[`score_tool_fit.py`](./score_tool_fit.py) holds the candidate universe and the
scoring model; [`tool_fit.json`](./tool_fit.json) is the generated output. Edit
`CANDIDATES` (or load your own list) and re-run to regenerate.

## Hard criteria (mandatory gates)

Applied **before** scoring — a company must pass **every** gate to be scored.

| Gate | Rule |
|---|---|
| **HQ in Taiwan** | Global corporate HQ legally domiciled in Taiwan (not just a Taiwan-born founder or a regional office). |
| **Well-established** | Publicly listed / clear market leader, founded on or before 2011 (≥ ~15y as of 2026). |

Latest run: **36 candidates → 33 passed → 3 excluded.**
Excluded: **Wiwynn** (founded 2012, not yet established), **Supermicro** (HQ USA),
**Garmin** (HQ USA). They sit in the candidate list as negative controls so the
gates are demonstrably doing work.

## Scoring model

Each survivor is scored **0–100 per product** from per-company signals in `[0,1]`
(`oss`, `sbom_pull`, `embedded`, `ai`, `web`, `protocol`, `safety`):

| Product | Formula |
|---|---|
| **Black Duck (SCA + SBOM)** | `100·(0.70·oss + 0.30·sbom_pull)` |
| **Coverity (SAST) + LLM/AI-SAST** | `100·(0.72·embedded + 0.28·ai)` |
| **DAST** | `100·web` |
| **Defensics (fuzzing)** | `100·(0.80·protocol + 0.20·safety)` |

**Lead selection.** Black Duck is the universal default (it scores high for
everyone). A challenger leads if it beats the Black Duck baseline, or — for the
**differentiated wedges** Defensics/Coverity — if it scores ≥ 78 and within 8 of
Black Duck. This encodes the rubric: default Black Duck, overridden by a strong
protocol/safety (Defensics) or large-embedded (Coverity) signal.

## Lead distribution (33 scored)

| Lead product | Count | Companies |
|---|:--:|---|
| **Black Duck (SCA + SBOM)** | 25 | Quanta, Wistron, Inventec, Foxconn, Compal, Pegatron, Advantech, Gigabyte, Accton, Sercomm, ADLINK, VIVOTEK, ASUS, Arcadyan, D-Link, Zyxel, ASRock, HTC, Acer, Andes, MSI, Innodisk, Novatek, Nuvoton, GUC |
| **Defensics (fuzzing)** | 4 | MediaTek, Realtek, Moxa, Delta Electronics |
| **DAST** | 2 | Synology, QNAP |
| **Coverity + LLM-SAST** | 2 | Phison, Silicon Motion |

## Top of the ranked table

| Company | HQ | BD | Cov | DAST | Def | **Lead** |
|---|---|:--:|:--:|:--:|:--:|---|
| Quanta Computer | Taoyuan | 92 | 54 | 68 | 47 | Black Duck |
| Wistron | Taipei | 89 | 50 | 58 | 41 | Black Duck |
| Inventec | Taipei | 89 | 49 | 56 | 40 | Black Duck |
| MediaTek | Hsinchu | 88 | 84 | 20 | 85 | **Defensics** |
| Hon Hai (Foxconn) | New Taipei | 87 | 56 | 55 | 55 | Black Duck |
| Advantech | Taipei | 86 | 60 | 60 | 74 | Black Duck |
| Realtek | Hsinchu | 84 | 73 | 15 | 78 | **Defensics** |
| Synology | New Taipei | 82 | 59 | 88 | 52 | **DAST** |
| Moxa | New Taipei | 82 | 56 | 55 | 81 | **Defensics** |
| Delta Electronics | Taipei | 82 | 63 | 52 | 80 | **Defensics** |
| QNAP | New Taipei | 82 | 56 | 86 | 50 | **DAST** |
| Phison | Miaoli | 69 | 73 | 10 | 52 | **Coverity** |
| Silicon Motion | Hsinchu | 69 | 73 | 10 | 54 | **Coverity** |

Full set of 33 with reasons, artifacts, mandate clauses and wedges in
[`tool_fit.json`](./tool_fit.json).

## Reading the logic

Black Duck leads the majority because SBOM is the universal, lowest-friction
wedge — every Phase 2/5 company ships code built on OSS and SBOM is an explicit
deliverable under CRA / EO 14028 / hyperscaler / IEC 62443 contracts (the server
ODMs Quanta/Wistron/Inventec score highest here on hyperscaler+federal SBOM
pull). Defensics overrides where the company **authors** comms/protocol stacks
(MediaTek, Realtek) or OT protocols (Moxa, Delta), since fuzz/robustness is the
differentiated wedge that R155/21434 and IEC 62443 explicitly expect. Coverity
leads the flash-controller firmware houses (Phison, Silicon Motion), where a
large in-house embedded codebase dominates and the OSS/web surface is thin. DAST
leads the NAS web-OS vendors (Synology, QNAP), whose internet-facing DSM/QTS
apps are the primary attack surface.

> **Note:** `signals` are analyst priors, not audited measurements. Refine them
> per company (or wire in real telemetry) and re-run to update the rankings.
