"""cvss-estimator: CVSS v3.1 base-score math + evidence-driven vector estimation.

Public API
----------
Scoring (official spec math):
- :func:`cvss_base_score`, :func:`cvss_vector`, :func:`parse_vector`,
  :func:`severity`, :func:`validate_metrics`.

Estimation (heuristic):
- :func:`impact_profile`, :func:`estimate_metrics`, :func:`estimate`.
"""

from __future__ import annotations

from ._core import (
    cvss_base_score,
    cvss_vector,
    estimate,
    estimate_metrics,
    impact_profile,
    parse_vector,
    severity,
    validate_metrics,
)

__all__ = [
    "cvss_base_score",
    "cvss_vector",
    "parse_vector",
    "severity",
    "validate_metrics",
    "impact_profile",
    "estimate_metrics",
    "estimate",
]
__version__ = "0.1.0"
