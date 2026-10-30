"""Fail the required check unless every declared prerequisite succeeded."""
import json
import os
import sys


def check_results(results):
    if not isinstance(results, dict) or not results:
        raise ValueError("needs must be a non-empty object")
    failed = []
    for name, job in results.items():
        if not isinstance(job, dict) or job.get("result") != "success":
            failed.append(name)
    return failed


def main():
    try:
        results = json.loads(os.environ["CI_NEEDS_JSON"])
        failed = check_results(results)
    except (KeyError, ValueError, TypeError) as exc:
        print(f"Invalid CI results: {exc}", file=sys.stderr)
        return 1
    for name, job in results.items():
        state = job.get("result", "missing") if isinstance(job, dict) else "invalid"
        print(f"{name}: {state}")
    if failed:
        print("Required jobs did not succeed: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
