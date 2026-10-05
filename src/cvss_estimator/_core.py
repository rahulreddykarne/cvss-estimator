"""CVSS v3.1 base-score math plus an evidence-driven vector estimator.

Two independent layers:

1. A dependency-free CVSS v3.1 base-score calculator (:func:`cvss_base_score`,
   :func:`cvss_vector`, :func:`parse_vector`, :func:`severity`). This implements
   the official specification arithmetic.

2. A heuristic that *estimates* a plausible CVSS vector from source-to-sink
   evidence flags and a vulnerability category (:func:`impact_profile`,
   :func:`estimate_metrics`, :func:`estimate`). Use it to generate a stable,
   explainable baseline vector for a finding before a human refines it.
"""

from __future__ import annotations

from math import ceil
from typing import Any, Optional

_METRIC_OPTIONS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}
_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


# --------------------------------------------------------------------------- #
# Layer 1: official CVSS v3.1 base-score math
# --------------------------------------------------------------------------- #
def validate_metrics(metrics: dict[str, str]) -> dict[str, str]:
    """Return an uppercased copy of *metrics*, raising ValueError if invalid."""
    result: dict[str, str] = {}
    for key in _METRIC_ORDER:
        if key not in metrics:
            raise ValueError(f"missing base metric: {key}")
        value = str(metrics[key]).upper()
        if value not in _METRIC_OPTIONS[key]:
            raise ValueError(f"invalid value {value!r} for metric {key}")
        result[key] = value
    return result


def cvss_vector(metrics: dict[str, str]) -> str:
    """Render a ``CVSS:3.1/...`` vector string from a base-metrics dict."""
    m = validate_metrics(metrics)
    return "CVSS:3.1/" + "/".join(f"{key}:{m[key]}" for key in _METRIC_ORDER)


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/...`` vector string into a base-metrics dict."""
    parts = [p for p in vector.strip().split("/") if p]
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()
    return validate_metrics(metrics)


def cvss_base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS v3.1 base score (0.0–10.0) from a base-metrics dict."""
    m = validate_metrics(metrics)
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
    scope_changed = m["S"] == "C"
    pr = (pr_c if scope_changed else pr_u)[m["PR"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
    c = impact_values[m["C"]]
    i = impact_values[m["I"]]
    a = impact_values[m["A"]]

    impact_sub = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)
    else:
        impact = 6.42 * impact_sub
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)
    return _round_up_1_decimal(base)


def severity(score: float) -> str:
    """Map a CVSS base score to its qualitative band."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _round_up_1_decimal(value: float) -> float:
    return ceil(value * 10) / 10.0


# --------------------------------------------------------------------------- #
# Layer 2: evidence-driven estimation
# --------------------------------------------------------------------------- #
def impact_profile(cwe: str = "", summary: str = "", finding_id: str = "") -> dict[str, Any]:
    """Classify a finding into an impact category with a sink-danger weight."""
    text = f"{finding_id} {cwe} {summary}".lower()
    cwe_num = "".join(ch for ch in str(cwe) if ch.isdigit())

    if cwe_num in {"502", "94", "78"} or any(
        token in text
        for token in (
            "yaml", "pickle", "deserial", "template", "ssti", "subprocess",
            "command", "exec", "eval", "torch.load", "joblib.load",
            "cloudpickle", "dill",
        )
    ):
        return {
            "category": "remote_code_execution",
            "impacts": ["confidentiality", "integrity", "availability"],
            "sink_danger": 34,
        }
    if cwe_num == "89" or "sql" in text:
        return {"category": "sql_injection", "impacts": ["confidentiality", "integrity"], "sink_danger": 30}
    if cwe_num == "918" or "ssrf" in text:
        return {"category": "ssrf", "impacts": ["confidentiality", "availability"], "sink_danger": 28}
    if cwe_num == "611" or "xxe" in text or "external entity" in text:
        return {"category": "xxe", "impacts": ["confidentiality", "availability"], "sink_danger": 27}
    if cwe_num == "22" or "path traversal" in text or "extractall" in text:
        return {
            "category": "path_traversal",
            "impacts": ["confidentiality", "integrity", "availability"],
            "sink_danger": 27,
        }
    if cwe_num == "798" or "secret" in text or "credential" in text:
        return {"category": "secret_exposure", "impacts": ["confidentiality"], "sink_danger": 24}
    if cwe_num == "400" or "redos" in text:
        return {"category": "denial_of_service", "impacts": ["availability"], "sink_danger": 22}
    if cwe_num in {"208", "377", "367", "915"}:
        return {"category": "security_weakness", "impacts": ["confidentiality", "integrity"], "sink_danger": 18}
    return {"category": "unknown", "impacts": [], "sink_danger": 12}


def estimate_metrics(
    *,
    category: Optional[str] = None,
    cwe: str = "",
    summary: str = "",
    finding_id: str = "",
    evidence: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """Estimate CVSS v3.1 base metrics from a category and evidence flags.

    Recognised ``evidence`` booleans: ``attacker_path_complete``,
    ``entrypoint_found``, ``auth_guard_present``, ``consumer_opt_in_required``,
    ``sanitizer_or_allowlist_present``, ``safe_containment_present``. An
    ``entrypoint`` string (e.g. ``"http_route"``) and a ``verdict`` string
    (``"confirmed"``) further tune the vector.
    """
    ev = dict(evidence or {})
    if category is None:
        category = str(impact_profile(cwe, summary, finding_id)["category"])
    verdict = str(ev.get("verdict") or "").lower()
    entrypoint = str(ev.get("entrypoint") or "").lower()

    if "http" in entrypoint or "route" in entrypoint or category in {"ssrf", "xxe", "sql_injection"}:
        av = "N"
    elif category == "remote_code_execution" and (ev.get("entrypoint_found") or ev.get("attacker_path_complete")):
        av = "N"
    else:
        av = "L"

    ac = "L" if ev.get("attacker_path_complete") or verdict == "confirmed" else "H"
    pr = "L" if ev.get("auth_guard_present") else "N"
    ui = "R" if ev.get("consumer_opt_in_required") else "N"
    scope = "U"

    c = i = a = "N"
    if category == "remote_code_execution":
        c = i = a = "H"
    elif category == "sql_injection":
        c = i = "H"
        a = "L"
    elif category == "ssrf":
        c = "H" if ev.get("attacker_path_complete") else "L"
        i = "L"
        a = "L"
    elif category == "xxe":
        c = "H"
        i = "L"
        a = "L"
    elif category == "path_traversal":
        c = "L"
        i = "H"
        a = "H"
    elif category == "secret_exposure":
        c = "H"
    elif category == "denial_of_service":
        a = "H"
    elif category == "security_weakness":
        c = i = "L"

    if ev.get("sanitizer_or_allowlist_present") or ev.get("safe_containment_present"):
        c = _downgrade_impact(c)
        i = _downgrade_impact(i)
        a = _downgrade_impact(a)
        ac = "H"

    if str(finding_id).upper().startswith("AST-DEPCONF"):
        ui = "R"
        ac = "H"

    return {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": scope, "C": c, "I": i, "A": a}


def estimate(
    *,
    category: Optional[str] = None,
    cwe: str = "",
    summary: str = "",
    finding_id: str = "",
    evidence: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return an estimated ``{metrics, vector, score, severity, impact_profile}``."""
    profile = impact_profile(cwe, summary, finding_id)
    metrics = estimate_metrics(
        category=category or profile["category"],
        cwe=cwe,
        summary=summary,
        finding_id=finding_id,
        evidence=evidence,
    )
    score = cvss_base_score(metrics)
    return {
        "metrics": metrics,
        "vector": cvss_vector(metrics),
        "score": score,
        "severity": severity(score),
        "impact_profile": profile,
    }


def _downgrade_impact(value: str) -> str:
    return {"H": "L", "L": "N"}.get(value, value)
