"""Deprecated entry point.

Production scanning uses ``core.analyzer.run_analysis`` only.
The dataset-registry experiment harness lives under ``research/experiment.py``.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> int:
    research = Path(__file__).resolve().parent / "research" / "experiment.py"
    if not research.is_file():
        print(
            "Research experiment harness not found. "
            "Use: python -m vulscan analyze ... (production path via core.analyzer)",
            file=sys.stderr,
        )
        return 2
    print(
        "[deprecated] experiment.py moved to research/experiment.py. "
        "Production scans must use core.analyzer / vulscan CLI.",
        file=sys.stderr,
    )
    sys.argv[0] = str(research)
    runpy.run_path(str(research), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
