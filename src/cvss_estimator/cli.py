"""Command-line interface for cvss-estimator.

Two modes:

* ``cvss-estimator score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``
* ``cvss-estimator estimate --cwe CWE-502 --complete-path``
"""

from __future__ import annotations

import argparse
import json

from ._core import cvss_base_score, estimate, parse_vector, severity


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvss-estimator", description="CVSS v3.1 scoring and estimation.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_score = sub.add_parser("score", help="score an existing CVSS:3.1 vector")
    p_score.add_argument("vector", help='e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')

    p_est = sub.add_parser("estimate", help="estimate a vector from evidence")
    p_est.add_argument("--cwe", default="", help="e.g. CWE-502")
    p_est.add_argument("--summary", default="", help="short finding description")
    p_est.add_argument("--complete-path", action="store_true", help="attacker source-to-sink path is complete")
    p_est.add_argument("--entrypoint", default="", help="entrypoint hint, e.g. http_route")
    p_est.add_argument("--auth-guard", action="store_true", help="an auth guard is present")
    p_est.add_argument("--opt-in", action="store_true", help="consumer opt-in required")
    p_est.add_argument("--sanitized", action="store_true", help="sanitizer/allowlist present")
    p_est.add_argument("--json", action="store_true", help="emit raw JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "score":
        metrics = parse_vector(args.vector)
        score = cvss_base_score(metrics)
        print(f"score:    {score}")
        print(f"severity: {severity(score)}")
        return 0

    evidence = {
        "attacker_path_complete": args.complete_path,
        "entrypoint": args.entrypoint,
        "entrypoint_found": bool(args.entrypoint),
        "auth_guard_present": args.auth_guard,
        "consumer_opt_in_required": args.opt_in,
        "sanitizer_or_allowlist_present": args.sanitized,
    }
    result = estimate(cwe=args.cwe, summary=args.summary, evidence=evidence)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"category: {result['impact_profile']['category']}")
        print(f"vector:   {result['vector']}")
        print(f"score:    {result['score']}")
        print(f"severity: {result['severity']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
