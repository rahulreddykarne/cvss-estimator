<div align="center">

# cvss-estimator

**Compute CVSS v3.1 base scores and estimate a full vector from source-to-sink evidence — with no dependencies.**

[![PyPI](https://img.shields.io/pypi/v/cvss-estimator?color=blue)](https://pypi.org/project/cvss-estimator/)
[![Python](https://img.shields.io/pypi/pyversions/cvss-estimator)](https://pypi.org/project/cvss-estimator/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/cvss-estimator/month)](https://pepy.tech/project/cvss-estimator)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

</div>

---

Two things in one small, **dependency-free** package:

1. **A correct CVSS v3.1 base-score calculator** — build, parse, and score
   vectors per the official specification arithmetic.
2. **An evidence-driven estimator** — turn source-to-sink evidence flags (is the
   attacker path complete? is there a sanitizer? a public entrypoint?) plus a
   CWE/summary into a plausible, explainable CVSS vector and score. Useful for
   generating a stable machine baseline before a human refines it.

## Highlights

- Spec-accurate CVSS v3.1 base-score arithmetic
- Parse, build and validate vector strings
- Explainable vector estimates from evidence flags and CWE
- Zero dependencies; library and CLI

## Install

```bash
pip install cvss-estimator
```

## Scoring an existing vector

```python
from cvss_estimator import cvss_base_score, parse_vector, severity

metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
score = cvss_base_score(metrics)   # 9.8
print(severity(score))             # "Critical"
```

```bash
cvss-estimator score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

## Estimating a vector from evidence

```python
from cvss_estimator import estimate

result = estimate(
    cwe="CWE-502",  # unsafe deserialization -> RCE category
    evidence={
        "attacker_path_complete": True,   # full source-to-sink -> AC:L, AV:N
        "entrypoint_found": True,
        "sanitizer_or_allowlist_present": False,
    },
)
print(result["vector"])    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
print(result["score"])     # 9.8
print(result["severity"])  # Critical
```

```bash
cvss-estimator estimate --cwe CWE-502 --complete-path --entrypoint http_route
```

### Evidence flags

| Flag | Effect |
| --- | --- |
| `attacker_path_complete` | `AC:L` (and `AV:N` for RCE) |
| `entrypoint` / `entrypoint_found` | network attack vector for RCE |
| `auth_guard_present` | `PR:L` |
| `consumer_opt_in_required` | `UI:R` |
| `sanitizer_or_allowlist_present` | downgrades C/I/A, raises `AC:H` |
| `safe_containment_present` | downgrades C/I/A, raises `AC:H` |

Categories are inferred from CWE/summary via `impact_profile()`:
`remote_code_execution`, `sql_injection`, `ssrf`, `xxe`, `path_traversal`,
`secret_exposure`, `denial_of_service`, `security_weakness`.

## Notes

- No runtime dependencies.
- The estimator is a **heuristic baseline**, not an authoritative score — always
  have a human confirm the vector before publishing a CVE.

## Development

```bash
git clone https://github.com/rahulreddykarne/cvss-estimator.git
cd cvss-estimator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m build
```

Bug reports and pull requests are welcome on the [issue tracker](https://github.com/rahulreddykarne/cvss-estimator/issues).

## Related projects

Part of a small toolkit for Python supply-chain security research:

| Project | What it does |
| --- | --- |
| [pypi-bulk-download](https://github.com/rahulreddykarne/pypi-bulk-download) | Bulk-download top PyPI packages in parallel with safe unpacking. |
| [tarslip-guard](https://github.com/rahulreddykarne/tarslip-guard) | Detect unsafe extractall() calls and safely extract tar/zip archives. |
| [pypi-version-bisect](https://github.com/rahulreddykarne/pypi-version-bisect) | Find a vulnerability's affected version range in O(log n) checks. |
| [pypi-blast-radius](https://github.com/rahulreddykarne/pypi-blast-radius) | Estimate the downstream impact of a PyPI package version. |
| [osv-dedupe](https://github.com/rahulreddykarne/osv-dedupe) | Score security findings against published OSV/NVD advisories. |
| [installtime-audit](https://github.com/rahulreddykarne/installtime-audit) | Flag install-time side effects in setup.py and friends. |

## License

Released under the [MIT License](LICENSE).
