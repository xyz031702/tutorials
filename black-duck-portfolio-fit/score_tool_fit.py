#!/usr/bin/env python3
"""Black Duck portfolio tool_fit scorer.

Pipeline:
  1. Start from a candidate universe of companies.
  2. Apply HARD CRITERIA gates (HQ in Taiwan, well-established) -> drop failures.
  3. Score each survivor 0-100 against EACH product from per-company signals.
  4. Pick the recommended LEAD via weighted-max (default Black Duck unless a
     stronger Defensics/Coverity signal dominates by a margin).
  5. Emit tool_fit.json + a ranked console table.

Scoring is signal-driven so it is reproducible, not hand-tuned per company.
Edit CANDIDATES (or load your own list) and re-run to regenerate.
"""
from __future__ import annotations
import json
import os

# --- Hard criteria ----------------------------------------------------------
# Gates are applied BEFORE scoring. A company must pass every gate.
WELL_ESTABLISHED_MAX_FOUNDED = 2011  # founded on/before -> >= ~15y as of 2026

def passes_hard_criteria(c: dict) -> tuple[bool, dict]:
    gates = {
        "hq_taiwan": c["hq_country"] == "Taiwan",
        "well_established": (c["founded"] <= WELL_ESTABLISHED_MAX_FOUNDED)
                            and bool(c.get("established_market_leader", True)),
    }
    return all(gates.values()), gates

# --- Signal -> product scoring ---------------------------------------------
# Signals are analyst priors in [0,1]:
#   oss      : ships code built on OSS (Black Duck driver) -- near-universal
#   sbom_pull: strength of SBOM contractual/regulatory pull (hyperscaler/fed/CRA)
#   embedded : size of in-house C/C++ embedded codebase shipped externally
#   ai       : AI/ML code or heavy AI-codegen usage (LLM-SAST booster)
#   web      : owned web/app/API/OTA/cloud attack surface
#   protocol : authoring of comms/protocol/OT/safety interface stacks
#   safety   : safety-critical interfaces
SIGNAL_KEYS = ("oss", "sbom_pull", "embedded", "ai", "web", "protocol", "safety")

def score_products(s: dict) -> dict:
    black_duck = 100 * (0.70 * s["oss"] + 0.30 * s["sbom_pull"])
    coverity   = 100 * (0.72 * s["embedded"] + 0.28 * s["ai"])   # LLM-SAST via `ai`
    dast       = 100 * s["web"]
    defensics  = 100 * (0.80 * s["protocol"] + 0.20 * s["safety"])
    return {
        "black_duck_sca_sbom": round(black_duck),
        "coverity_sast": round(coverity),
        "dast": round(dast),
        "defensics_fuzzing": round(defensics),
    }

PRODUCT_LABEL = {
    "black_duck_sca_sbom": "Black Duck (SCA + SBOM)",
    "coverity_sast": "Coverity (SAST) + LLM/AI-assisted SAST",
    "dast": "DAST",
    "defensics_fuzzing": "Defensics (protocol/file/interface fuzzing)",
}

# Lead selection. Black Duck is the universal default (it scores high for
# everyone), so a challenger leads only when it genuinely beats the Black Duck
# baseline OR -- for the two DIFFERENTIATED wedges (Defensics, Coverity) -- when
# its signal is strong in absolute terms and at least competitive with Black
# Duck. This encodes the rubric: default Black Duck, but a strong protocol/safety
# (Defensics) or large-embedded (Coverity) signal overrides it.
DIFFERENTIATED = ("defensics_fuzzing", "coverity_sast")
STRONG_ABS = 78   # a differentiated wedge must clear this to override the default
NEAR_BAND = 8     # ...and sit within this margin of the Black Duck baseline

def pick_lead(scores: dict) -> str:
    bd = scores["black_duck_sca_sbom"]
    eligible = {}
    for k, v in scores.items():
        if k == "black_duck_sca_sbom":
            continue
        if v > bd:
            eligible[k] = v
        elif k in DIFFERENTIATED and v >= STRONG_ABS and v >= bd - NEAR_BAND:
            eligible[k] = v
    if eligible:
        return max(eligible, key=eligible.get)
    return "black_duck_sca_sbom"

WEDGE = {
    "black_duck_sca_sbom": "SBOM-first: inventory the OSS in {artifact} to clear CRA / EO 14028 / contract gates.",
    "coverity_sast": "Static-analysis wedge on the in-house code in {artifact}; LLM-SAST where it is AI-generated.",
    "dast": "Test the running web/app/API surface: {artifact}.",
    "defensics_fuzzing": "Fuzz the protocol/interface stacks you author: {artifact}.",
}

# --- Candidate universe -----------------------------------------------------
# Well-established Taiwan-HQ companies across the archetypes the portfolio sells
# into. `signals` are analyst priors; `lead_artifact` feeds the wedge template.
def C(name, hq_city, hq_country, founded, listing, archetype, phase,
      lead_artifact, mandate, **signals):
    base = {k: 0.0 for k in SIGNAL_KEYS}
    base.update(signals)
    return dict(company=name, hq=f"{hq_city}, {hq_country}", hq_country=hq_country,
                founded=founded, listing=listing, archetype=archetype, phase=phase,
                lead_artifact=lead_artifact, mandate=mandate, signals=base)

CANDIDATES = [
    # --- Semiconductor / SoC / connectivity (protocol authors) ---
    C("MediaTek", "Hsinchu", "Taiwan", 1997, "TWSE:2454", "Connectivity SoC / firmware + SDK", "Phase 2",
      "5G/Wi-Fi/BT/Thread comms stacks", "ISO 21434 + IEC 62443 fuzz; CRA",
      oss=.90, sbom_pull=.85, embedded=.95, ai=.55, web=.20, protocol=.95, safety=.45),
    C("Realtek Semiconductor", "Hsinchu", "Taiwan", 1987, "TWSE:2379", "Networking/connectivity/audio SoC + drivers", "Phase 2",
      "Ethernet/Wi-Fi/BT/USB stacks", "IEC 62443 + CRA interface robustness",
      oss=.85, sbom_pull=.80, embedded=.92, ai=.25, web=.15, protocol=.92, safety=.20),
    C("Novatek Microelectronics", "Hsinchu", "Taiwan", 1997, "TWSE:3034", "Display driver / SoC", "Phase 2",
      "Display/SoC firmware + reference SDK", "CRA SBOM passthrough; SSDF",
      oss=.78, sbom_pull=.70, embedded=.85, ai=.20, web=.10, protocol=.45, safety=.15),
    C("Nuvoton Technology", "Hsinchu", "Taiwan", 2008, "TWSE:4919", "MCU / BMC security chip", "Phase 2",
      "MCU/BMC firmware + protocol handling", "SSDF; IEC 62443",
      oss=.75, sbom_pull=.72, embedded=.88, ai=.20, web=.10, protocol=.70, safety=.45),
    C("Phison Electronics", "Miaoli", "Taiwan", 2000, "TWSE:8299", "NAND flash controller", "Phase 2",
      "Storage controller firmware + host interface", "SSDF; CRA SBOM passthrough",
      oss=.70, sbom_pull=.68, embedded=.90, ai=.30, web=.10, protocol=.60, safety=.20),
    C("Silicon Motion", "Hsinchu", "Taiwan", 1995, "NASDAQ:SIMO/TW", "NAND/SSD controller", "Phase 2",
      "SSD controller firmware + NVMe/host interface", "SSDF; CRA SBOM passthrough",
      oss=.70, sbom_pull=.68, embedded=.90, ai=.30, web=.10, protocol=.62, safety=.20),
    C("Andes Technology", "Hsinchu", "Taiwan", 2005, "TWSE:6533", "RISC-V CPU IP + toolchain", "Phase 2",
      "CPU IP, toolchain and reference SDK", "SSDF; supply-chain transparency",
      oss=.82, sbom_pull=.70, embedded=.80, ai=.35, web=.15, protocol=.30, safety=.30),
    C("Global Unichip (GUC)", "Hsinchu", "Taiwan", 1998, "TWSE:3443", "ASIC design service", "Phase 2",
      "Custom ASIC firmware + IP integration", "SSDF; customer SBOM passthrough",
      oss=.72, sbom_pull=.68, embedded=.78, ai=.25, web=.10, protocol=.40, safety=.20),

    # --- Consumer device brands (apps + cloud) ---
    C("ASUS (ASUSTeK)", "Taipei", "Taiwan", 1989, "TWSE:2357", "Consumer device + companion apps/cloud", "Phase 5",
      "device firmware + companion app/cloud/OTA", "CRA; EO 14028/NTIA SBOM",
      oss=.85, sbom_pull=.78, embedded=.60, ai=.40, web=.82, protocol=.55, safety=.20),
    C("Acer", "New Taipei", "Taiwan", 1976, "TWSE:2353", "PC / device brand + services", "Phase 5",
      "device firmware + service portals/cloud", "CRA; EO 14028 SBOM",
      oss=.82, sbom_pull=.72, embedded=.50, ai=.40, web=.72, protocol=.35, safety=.15),
    C("Gigabyte Technology", "New Taipei", "Taiwan", 1986, "TWSE:2376", "Motherboard / GPU / server builder", "Phase 5",
      "board/server firmware + BMC management UI", "EO 14028 SBOM; hyperscaler; CRA",
      oss=.86, sbom_pull=.80, embedded=.66, ai=.35, web=.62, protocol=.50, safety=.15),
    C("Micro-Star Intl (MSI)", "New Taipei", "Taiwan", 1986, "TWSE:2377", "Motherboard / laptop / device brand", "Phase 5",
      "board/laptop firmware + companion apps", "CRA; EO 14028 SBOM",
      oss=.82, sbom_pull=.70, embedded=.55, ai=.35, web=.60, protocol=.40, safety=.15),
    C("ASRock", "Taipei", "Taiwan", 2002, "TWSE:3515", "Motherboard / IPC builder", "Phase 5",
      "board/IPC firmware + BMC UI", "EO 14028 SBOM; CRA",
      oss=.84, sbom_pull=.74, embedded=.62, ai=.25, web=.58, protocol=.45, safety=.15),
    C("HTC", "Taoyuan", "Taiwan", 1997, "TWSE:2498", "Smartphone / XR device brand", "Phase 5",
      "device firmware + companion apps/cloud + XR runtime", "CRA; EO 14028 SBOM",
      oss=.84, sbom_pull=.70, embedded=.62, ai=.55, web=.78, protocol=.55, safety=.20),

    # --- Networking / CPE / router ODM (protocol + web) ---
    C("Accton Technology", "Hsinchu", "Taiwan", 1988, "TWSE:2345", "Networking / switch ODM", "Phase 5",
      "switch/router firmware + management UI", "EO 14028 SBOM; IEC 62443; CRA",
      oss=.86, sbom_pull=.80, embedded=.70, ai=.25, web=.62, protocol=.78, safety=.20),
    C("Sercomm", "Taipei", "Taiwan", 1992, "TWSE:5388", "Broadband CPE / IoT gateway ODM", "Phase 5",
      "CPE/gateway firmware + remote mgmt (TR-069)", "CRA; carrier SBOM; IEC 62443",
      oss=.86, sbom_pull=.78, embedded=.66, ai=.25, web=.68, protocol=.80, safety=.20),
    C("Arcadyan Technology", "Hsinchu", "Taiwan", 2003, "TWSE:3596", "Broadband CPE / router ODM", "Phase 5",
      "router/CPE firmware + TR-069 mgmt", "CRA; carrier SBOM",
      oss=.85, sbom_pull=.76, embedded=.64, ai=.20, web=.66, protocol=.80, safety=.18),
    C("D-Link", "Taipei", "Taiwan", 1986, "TWSE:2332", "Networking device brand", "Phase 5",
      "router/AP/camera firmware + cloud apps", "CRA; EO 14028 SBOM",
      oss=.85, sbom_pull=.74, embedded=.58, ai=.25, web=.74, protocol=.72, safety=.18),
    C("Zyxel Communications", "Hsinchu", "Taiwan", 1989, "private", "Networking / security appliance", "Phase 5",
      "firewall/router firmware + web mgmt", "CRA; IEC 62443; SBOM",
      oss=.85, sbom_pull=.74, embedded=.62, ai=.25, web=.76, protocol=.74, safety=.20),

    # --- Server / ODM / EMS (hyperscaler SBOM) ---
    C("Quanta Computer", "Taoyuan", "Taiwan", 1988, "TWSE:2382", "Server / notebook ODM (hyperscaler)", "Phase 5",
      "server/notebook platform + BMC firmware", "EO 14028 federal SBOM; hyperscaler; CRA",
      oss=.92, sbom_pull=.92, embedded=.62, ai=.35, web=.68, protocol=.55, safety=.15),
    C("Wiwynn", "New Taipei", "Taiwan", 2012, "TWSE:6669", "Hyperscale cloud server ODM", "Phase 5",
      "cloud server platform + OpenBMC firmware", "EO 14028 SBOM; hyperscaler OCP; CRA",
      oss=.92, sbom_pull=.93, embedded=.58, ai=.30, web=.60, protocol=.50, safety=.12,
      established_market_leader=True),
    C("Wistron", "Taipei", "Taiwan", 2001, "TWSE:3231", "Server / device ODM", "Phase 5",
      "server/device platform + BMC firmware", "EO 14028 SBOM; hyperscaler; CRA",
      oss=.90, sbom_pull=.88, embedded=.58, ai=.30, web=.58, protocol=.48, safety=.15),
    C("Inventec", "Taipei", "Taiwan", 1975, "TWSE:2356", "Server / device ODM", "Phase 5",
      "server/device platform + BMC firmware", "EO 14028 SBOM; hyperscaler; CRA",
      oss=.90, sbom_pull=.88, embedded=.56, ai=.30, web=.56, protocol=.46, safety=.15),
    C("Compal Electronics", "Taipei", "Taiwan", 1984, "TWSE:2324", "Notebook / device ODM", "Phase 5",
      "notebook/device firmware platform", "EO 14028 SBOM; CRA",
      oss=.88, sbom_pull=.82, embedded=.54, ai=.30, web=.50, protocol=.45, safety=.15),
    C("Pegatron", "Taipei", "Taiwan", 2008, "TWSE:4938", "EMS / device ODM", "Phase 5",
      "device firmware platform + integration", "EO 14028 SBOM; CRA",
      oss=.88, sbom_pull=.82, embedded=.52, ai=.30, web=.50, protocol=.45, safety=.18),
    C("Hon Hai (Foxconn)", "New Taipei", "Taiwan", 1974, "TWSE:2317", "EMS / device + EV builder", "Phase 5",
      "device/EV firmware platform + integration", "EO 14028 SBOM; CRA; R155 (EV)",
      oss=.88, sbom_pull=.84, embedded=.60, ai=.45, web=.55, protocol=.58, safety=.45),

    # --- Industrial / edge / OT (protocol authors) ---
    C("Advantech", "Taipei", "Taiwan", 1983, "TWSE:2395", "Industrial edge gateway / IPC", "Phase 5",
      "edge gateway/IPC firmware + Modbus/OPC-UA stacks", "IEC 62443-4-1 SBOM; CRA",
      oss=.88, sbom_pull=.80, embedded=.70, ai=.35, web=.60, protocol=.82, safety=.40),
    C("Moxa", "New Taipei", "Taiwan", 1987, "private", "Industrial networking / OT connectivity", "Phase 5",
      "Modbus/EtherNet-IP/PROFINET protocol stacks", "IEC 62443-4-2 fuzz; CRA",
      oss=.84, sbom_pull=.78, embedded=.70, ai=.20, web=.55, protocol=.90, safety=.45),
    C("ADLINK Technology", "Taipei", "Taiwan", 1995, "TWSE:6166", "Edge computing / industrial IPC", "Phase 5",
      "edge/IPC firmware + industrial protocol stacks", "IEC 62443 SBOM/robustness; CRA",
      oss=.86, sbom_pull=.78, embedded=.68, ai=.50, web=.55, protocol=.80, safety=.45),
    C("Delta Electronics", "Taipei", "Taiwan", 1971, "TWSE:2308", "Industrial automation / power / EV", "Phase 5",
      "PLC/drive/EV-charger firmware + OT protocols", "IEC 62443 robustness; R155 (EV); CRA",
      oss=.84, sbom_pull=.78, embedded=.72, ai=.40, web=.52, protocol=.85, safety=.60),
    C("Innodisk", "New Taipei", "Taiwan", 2005, "TWSE:5289", "Industrial storage / embedded peripherals", "Phase 2",
      "industrial SSD/module firmware", "IEC 62443; CRA SBOM passthrough",
      oss=.80, sbom_pull=.74, embedded=.82, ai=.30, web=.30, protocol=.55, safety=.30),
    C("VIVOTEK", "New Taipei", "Taiwan", 2000, "TWSE:3454", "IP surveillance camera", "Phase 5",
      "camera firmware + ONVIF/RTSP stacks + web/VMS", "CRA; NDAA; IEC 62443",
      oss=.86, sbom_pull=.78, embedded=.66, ai=.55, web=.80, protocol=.78, safety=.25),

    # --- Storage / NAS appliance (web surface) ---
    C("Synology", "New Taipei", "Taiwan", 2000, "TWSE:6783", "NAS / storage appliance + DSM web OS", "Phase 5",
      "DSM web UI / APIs / QuickConnect / cloud", "CRA secure-by-design; OWASP",
      oss=.86, sbom_pull=.74, embedded=.68, ai=.35, web=.88, protocol=.60, safety=.18),
    C("QNAP Systems", "New Taipei", "Taiwan", 2004, "private", "NAS / storage appliance + QTS web OS", "Phase 5",
      "QTS web UI / APIs / cloud + app center", "CRA secure-by-design; OWASP",
      oss=.86, sbom_pull=.72, embedded=.66, ai=.30, web=.86, protocol=.58, safety=.18),

    # --- Negative controls: present in candidate list but FAIL the hard gates ---
    C("Supermicro", "San Jose", "USA", 1993, "NASDAQ:SMCI", "Server / BMC builder", "Phase 5",
      "server platform + BMC firmware", "EO 14028 SBOM; hyperscaler",
      oss=.90, sbom_pull=.90, embedded=.78, ai=.30, web=.70, protocol=.55, safety=.15),
    C("Garmin", "Olathe", "USA", 1989, "NYSE:GRMN", "GPS wearables / avionics", "Phase 5",
      "device firmware + companion app/cloud", "CRA; EO 14028; DO-178 (avionics)",
      oss=.85, sbom_pull=.78, embedded=.80, ai=.40, web=.78, protocol=.70, safety=.55),
]


def build_record(c: dict) -> dict:
    scores = score_products(c["signals"])
    lead = pick_lead(scores)
    return {
        "company": c["company"],
        "hq": c["hq"],
        "founded": c["founded"],
        "listing": c["listing"],
        "archetype": c["archetype"],
        "phase": c["phase"],
        "fit_scores": scores,
        "recommended_lead": PRODUCT_LABEL[lead],
        "wedge": WEDGE[lead].format(artifact=c["lead_artifact"]),
        "lead_mandate_clause": c["mandate"],
    }


def main() -> None:
    scored, excluded = [], []
    for c in CANDIDATES:
        ok, gates = passes_hard_criteria(c)
        if ok:
            scored.append(build_record(c))
        else:
            failed = [g for g, v in gates.items() if not v]
            excluded.append({"company": c["company"], "hq": c["hq"], "failed_gates": failed})

    # Rank by the lead product's score, then by Black Duck baseline.
    def lead_score(r):
        inv = {v: k for k, v in PRODUCT_LABEL.items()}
        return r["fit_scores"][inv[r["recommended_lead"]]]
    scored.sort(key=lambda r: (lead_score(r), r["fit_scores"]["black_duck_sca_sbom"]), reverse=True)

    out = {
        "schema_version": "2.0",
        "generator": "score_tool_fit.py",
        "hard_criteria": {
            "gates": [
                {"id": "hq_taiwan", "rule": "Global corporate HQ legally domiciled in Taiwan."},
                {"id": "well_established",
                 "rule": f"Publicly listed / market leader founded on or before {WELL_ESTABLISHED_MAX_FOUNDED} (>= ~15y)."},
            ],
            "candidates_evaluated": len(CANDIDATES),
            "passed": len(scored),
            "excluded": excluded,
        },
        "scoring_model": {
            "signals": list(SIGNAL_KEYS),
            "formulas": {
                "black_duck_sca_sbom": "100*(0.70*oss + 0.30*sbom_pull)",
                "coverity_sast": "100*(0.72*embedded + 0.28*ai)",
                "dast": "100*web",
                "defensics_fuzzing": "100*(0.80*protocol + 0.20*safety)",
            },
            "lead_rule": (f"Default Black Duck. A challenger leads if it beats the Black Duck "
                          f"baseline, or -- for the differentiated wedges {DIFFERENTIATED} -- "
                          f"if it scores >= {STRONG_ABS} and within {NEAR_BAND} of Black Duck."),
        },
        "companies": scored,
    }

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "tool_fit.json"), "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    # Console summary
    print(f"Candidates: {len(CANDIDATES)} | Passed gates: {len(scored)} | Excluded: {len(excluded)}")
    print(f"{'Company':28} {'HQ':18} {'BD':>3} {'Cov':>3} {'DAST':>4} {'Def':>3}  Lead")
    print("-" * 92)
    for r in scored:
        s = r["fit_scores"]
        print(f"{r['company']:28.28} {r['hq']:18.18} "
              f"{s['black_duck_sca_sbom']:3d} {s['coverity_sast']:3d} "
              f"{s['dast']:4d} {s['defensics_fuzzing']:3d}  {r['recommended_lead'].split(' (')[0]}")
    if excluded:
        print("\nExcluded by hard gates:")
        for e in excluded:
            print(f"  - {e['company']} ({e['hq']}): failed {', '.join(e['failed_gates'])}")


if __name__ == "__main__":
    main()
