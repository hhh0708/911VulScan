#!/usr/bin/env python3
"""CLI for generating a neutral application-context fact layer.

Usage:
    python -m context.generate_context /path/to/repo
    python -m context.generate_context /path/to/repo -o context.json
    python -m context.generate_context /path/to/repo --parse-dir /path/to/run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from context.application_context import (
    STATUS_UNAVAILABLE,
    format_context_for_prompt,
    generate_application_context,
    save_context,
)
from utilities.model_registry import ModelRole, model_for


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a neutral application-context fact layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Application context is a NEUTRAL fact layer. It does not classify fixed
application types, apply repo override files as security policy, or declare
behaviors safe.

Examples:
    python -m context.generate_context /path/to/repo
    python -m context.generate_context /path/to/repo --parse-dir ./runs/rid
        """,
    )
    parser.add_argument("repo_path", type=Path, help="Repository path")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON path")
    parser.add_argument(
        "--model",
        "-m",
        default=model_for(ModelRole.SECONDARY),
        help="Model id for generation",
    )
    parser.add_argument(
        "--parse-dir",
        type=Path,
        help="Directory containing dataset.json / call_graph.json from parse",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Path to dataset.json from parse stage",
    )
    parser.add_argument(
        "--show-prompt",
        action="store_true",
        help="Show the formatted context as injected into prompts",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    # Deprecated flags kept so old scripts don't crash.
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--list-types",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.list_types:
        print(
            "Fixed ApplicationType classification has been removed.\n"
            "App Context is a neutral fact layer (purpose, components, interfaces, …)."
        )
        sys.exit(0)

    if not args.repo_path.exists() or not args.repo_path.is_dir():
        print(f"Error: invalid repository path: {args.repo_path}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or args.repo_path / "application_context.json"
    context = generate_application_context(
        args.repo_path,
        model=args.model,
        dataset_path=args.dataset,
        parse_artifacts_dir=args.parse_dir,
    )
    save_context(context, output_path)

    if not args.quiet:
        print("=" * 60)
        print("APPLICATION CONTEXT (neutral)")
        print("=" * 60)
        print(f"Status:  {context.status}")
        print(f"Purpose: {context.purpose or '(none)'}")
        if context.status == STATUS_UNAVAILABLE:
            print("Context unavailable — pipeline may continue without facts.")
        else:
            print(f"Components: {len(context.components)}")
            print(f"Exposed interfaces: {len(context.exposed_interfaces)}")
            print(f"Claims (untrusted): {len(context.documented_security_claims)}")
            print(f"Unknowns: {len(context.unknowns)}")
        print(f"Saved: {output_path}")

    if args.show_prompt:
        print()
        print("=" * 60)
        print("PROMPT FORMAT")
        print("=" * 60)
        print(format_context_for_prompt(context))

    # Unavailable is not a hard failure for the CLI; exit 0 so automation continues.
    sys.exit(0)


if __name__ == "__main__":
    main()
