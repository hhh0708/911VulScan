#!/usr/bin/env python3
"""
Zig Parser Pipeline Orchestrator

Entry point for parsing Zig repositories. Wires together the 4-stage pipeline:
1. Repository Scanner
2. Function Extractor
3. Call Graph Builder
4. Unit Generator

Usage:
    python test_pipeline.py <repo_path> \
        --output <dir> \
        --processing-level <all|reachable|codeql|exploitable> \
        --skip-tests \
        --name <dataset_name>
"""

import argparse
import json
import sys
from pathlib import Path
from utilities.file_io import read_json, write_json

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.parser_adapter import apply_reachability_filter as _canonical_reachability_filter
from parsers.zig.repository_scanner import RepositoryScanner
from parsers.zig.function_extractor import FunctionExtractor
from parsers.zig.call_graph_builder import CallGraphBuilder
from parsers.zig.unit_generator import UnitGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Parse Zig repositories for vulnerability analysis"
    )
    parser.add_argument("repo_path", help="Path to the Zig repository")
    parser.add_argument(
        "--output", "-o", required=True, help="Output directory for results"
    )
    parser.add_argument(
        "--processing-level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="all",
        help="Processing level for filtering functions",
    )
    parser.add_argument(
        "--skip-tests", action="store_true", help="Skip test files and functions"
    )
    parser.add_argument("--name", help="Dataset name (defaults to repo directory name)")
    parser.add_argument(
        "--dependency-depth",
        type=int,
        default=3,
        help="Maximum depth for dependency resolution",
    )

    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output).resolve()

    if not repo_path.exists():
        print(f"Error: Repository path does not exist: {repo_path}", file=sys.stderr)
        return 1

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Zig Parser] Parsing repository: {repo_path}", file=sys.stderr)
    print(f"[Zig Parser] Output directory: {output_dir}", file=sys.stderr)
    print(f"[Zig Parser] Processing level: {args.processing_level}", file=sys.stderr)
    print(f"[Zig Parser] Skip tests: {args.skip_tests}", file=sys.stderr)

    try:
        # Stage 1: Repository Scanner
        print("[Zig Parser] Stage 1: Scanning repository...", file=sys.stderr)
        scanner = RepositoryScanner(
            str(repo_path),
            skip_tests=args.skip_tests,
        )
        scan_results = scanner.scan()
        scanner.save_results(str(output_dir / "scan_results.json"), scan_results)
        print(
            f"  Found {scan_results['statistics']['total_files']} Zig files",
            file=sys.stderr,
        )

        if scan_results["statistics"]["total_files"] == 0:
            print("[Zig Parser] No Zig files found in repository", file=sys.stderr)
            # Write empty dataset
            empty_dataset = {
                "name": args.name or repo_path.name,
                "repository": str(repo_path),
                "units": [],
                "statistics": {"total_units": 0, "by_type": {}},
                "metadata": {"generator": "zig_unit_generator.py"},
            }
            write_json(output_dir / "dataset.json", empty_dataset)
            write_json(output_dir / "analyzer_output.json", {"repository": str(repo_path), "functions": {}})
            return 0

        # Stage 2: Function Extractor
        print("[Zig Parser] Stage 2: Extracting functions...", file=sys.stderr)
        extractor = FunctionExtractor(str(repo_path), scan_results)
        extractor_output = extractor.extract()
        print(
            f"  Extracted {extractor_output['statistics']['total_functions']} functions",
            file=sys.stderr,
        )
        print(
            f"  Extracted {extractor_output['statistics']['total_classes']} structs",
            file=sys.stderr,
        )

        # Stage 3: Call Graph Builder
        print("[Zig Parser] Stage 3: Building call graph...", file=sys.stderr)
        call_graph_builder = CallGraphBuilder(extractor_output)
        call_graph_output = call_graph_builder.build()
        call_graph_builder.save_results(
            str(output_dir / "call_graph.json"), call_graph_output
        )
        try:
            from utilities.call_graph.schema import write_call_graph
            write_call_graph(
                str(output_dir / "call_graph.json"),
                call_graph_output,
                language="zig",
            )
        except Exception:
            pass
        print(
            f"  Built graph with {call_graph_output['statistics']['total_edges']} edges",
            file=sys.stderr,
        )

        # Stage 4: Unit Generator
        print("[Zig Parser] Stage 4: Generating analysis units...", file=sys.stderr)
        generator = UnitGenerator(
            call_graph_output,
            str(repo_path),
            dependency_depth=args.dependency_depth,
        )
        dataset, analyzer_output = generator.generate(name=args.name)
        generator.save_results(str(output_dir), dataset, analyzer_output)
        print(
            f"  Generated {dataset['statistics']['total_units']} units",
            file=sys.stderr,
        )

        if args.processing_level != "all":
            dataset_path = output_dir / "dataset.json"
            dataset = read_json(dataset_path)
            dataset = _canonical_reachability_filter(
                dataset, str(output_dir), args.processing_level
            )
            write_json(dataset_path, dataset)
            meta = dataset.get("metadata", {}).get("reachability_filter", {})
            print(
                f"  After {args.processing_level} filter: "
                f"{meta.get('kept_units', len(dataset.get('units', [])))} units kept",
                file=sys.stderr,
            )

        print("[Zig Parser] Pipeline complete!", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"[Zig Parser] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
