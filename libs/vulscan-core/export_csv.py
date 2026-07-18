#!/usr/bin/env python3
"""Export FinalScanArtifact findings to CSV (final_state sections only).

Legacy dataset + results.json + verdict columns are no longer supported.

Usage:
    python export_csv.py <pipeline_output.json> [output.csv]
"""

from __future__ import annotations

import argparse
import sys

from core.final_artifact.csv_export import write_csv_from_artifact
from core.final_artifact.finalize import (
    FinalArtifactIntegrityError,
    load_and_validate_final_artifact,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export FinalScanArtifact findings to CSV (no dataset required)."
    )
    parser.add_argument(
        "artifact",
        help="Path to pipeline_output.json (FinalScanArtifact)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        default="findings.csv",
        help="Output CSV path (default: findings.csv)",
    )
    args = parser.parse_args(argv)

    # Detect obsolete three-arg form: results.json dataset.json out.csv
    if len(sys.argv if argv is None else argv) >= 3:
        # If middle/extra looks like a dataset JSON, fail fast.
        candidates = list(sys.argv[1:] if argv is None else argv)
        if len(candidates) >= 3 and candidates[1].endswith(".json"):
            print(
                "ERROR: export_csv now requires a FinalScanArtifact "
                "(pipeline_output.json). Dataset argument is no longer accepted.",
                file=sys.stderr,
            )
            return 2

    try:
        artifact = load_and_validate_final_artifact(args.artifact)
    except FinalArtifactIntegrityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    write_csv_from_artifact(artifact, args.output)
    print(f"Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
