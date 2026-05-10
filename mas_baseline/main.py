"""
main.py
=======
Runner for the 5-agent MAS baseline.

Usage:
  python main.py                    # runs the 4 baseline test scenarios
  python main.py --query "..."      # runs a single custom query
"""

from __future__ import annotations
import sys
import json
import argparse
from research.mas_baseline.core.state import initial_state
from research.mas_baseline.graph import get_graph


# ─────────────────────────────────────────────────────────────────────────────
# Baseline test scenarios
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_SCENARIOS = [
    {
        "id":          "S1",
        "description": "Permitted read — editor queries user list",
        "query":       "Get all users from the system",
        "expect_auth": "approved",
    },
    {
        "id":          "S2",
        "description": "Permitted write — editor creates a record",
        "query":       "Save a new report record for Q2",
        "expect_auth": "approved",
    },
    {
        "id":          "S3",
        "description": "Denied operation — editor attempts delete",
        "query":       "Delete the record R001",
        "expect_auth": "denied",
    },
    {
        "id":          "S4",
        "description": "Denied operation — editor attempts admin action",
        "query":       "Configure system admin settings",
        "expect_auth": "denied",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_scenario(query: str, scenario_id: str = "CUSTOM") -> dict:
    """Run a single query through the full MAS pipeline."""
    graph = get_graph()
    state = initial_state(query)

    print(f"\n{'─'*60}")
    print(f"[Scenario {scenario_id}] Query: {query!r}")
    print(f"{'─'*60}")

    result = graph.invoke(state)

    # ── summary output ────────────────────────────────────────────────────────
    print(f"\n[Summary]")
    print(f"  Auth status    : {result.get('auth_status', 'N/A')}")
    print(f"  Task           : {result.get('current_task', 'N/A')}")
    print(f"  Anomaly found  : {result.get('anomaly_detected', False)}")
    print(f"  Messages in bus: {len(result.get('messages', []))}")
    print(f"  Log entries    : {len(result.get('logs', []))}")

    if result.get("anomaly_details"):
        print(f"\n  ⚠  Anomaly details:")
        for a in result["anomaly_details"]:
            print(f"     [{a.get('severity','?')}] Rule {a.get('rule','?')}: {a.get('message','')}")

    return result


def run_all_baseline():
    """Run all 4 baseline scenarios and print a summary table."""
    results = []
    for sc in BASELINE_SCENARIOS:
        print(f"\n{'='*60}")
        print(f"[{sc['id']}] {sc['description']}")
        result = run_scenario(sc["query"], sc["id"])
        auth_actual   = result.get("auth_status", "pending")
        auth_expected = sc["expect_auth"]
        passed        = auth_actual == auth_expected
        results.append({
            "id":       sc["id"],
            "desc":     sc["description"],
            "expected": auth_expected,
            "actual":   auth_actual,
            "passed":   passed,
            "anomaly":  result.get("anomaly_detected", False),
        })

    # ── print summary table ───────────────────────────────────────────────────
    print(f"\n\n{'='*60}")
    print("BASELINE TEST SUMMARY")
    print(f"{'='*60}")
    print(f"{'ID':<6} {'Expected':<12} {'Actual':<12} {'Pass':<8} {'Anomaly'}")
    print(f"{'─'*6} {'─'*12} {'─'*12} {'─'*8} {'─'*8}")
    all_passed = True
    for r in results:
        status = "✓" if r["passed"] else "✗"
        anomaly = "⚠" if r["anomaly"] else "-"
        print(f"{r['id']:<6} {r['expected']:<12} {r['actual']:<12} {status:<8} {anomaly}")
        if not r["passed"]:
            all_passed = False

    print(f"{'='*60}")
    print(f"Result: {'ALL PASSED ✓' if all_passed else 'SOME FAILED ✗'}")
    print(f"{'='*60}\n")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAS Baseline Runner")
    parser.add_argument("--query", type=str, default=None,
                        help="Run a single custom query")
    parser.add_argument("--verbose-messages", action="store_true",
                        help="Print full A2A message bus after each run")
    args = parser.parse_args()

    if args.query:
        result = run_scenario(args.query, "CUSTOM")
        if args.verbose_messages:
            print("\n[A2A Message Bus]")
            for msg in result.get("messages", []):
                print(json.dumps(msg, indent=2, default=str))
    else:
        run_all_baseline()
