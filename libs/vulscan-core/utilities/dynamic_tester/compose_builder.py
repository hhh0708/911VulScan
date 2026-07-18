"""Framework-owned docker-compose topology for attacker callback tests."""

from __future__ import annotations

import textwrap


def build_compose_yaml(
    *,
    test_image: str = "vulscan-test-service",
    test_command: str | None = None,
) -> str:
    """Return a hardened two-service compose file (test + internal attacker).

    LLM-provided compose YAML is never executed; this topology is authoritative.
    """
    test_cmd_line = ""
    if test_command:
        test_cmd_line = f"\n    command: {test_command}"

    return textwrap.dedent(
        f"""\
        services:
          test:
            build:
              context: .
              dockerfile: Dockerfile
            image: {test_image}
            depends_on:
              - attacker
            networks:
              - vulscan_internal
            cap_drop:
              - ALL
            security_opt:
              - no-new-privileges:true
            mem_limit: 512m
            cpus: 1
            pids_limit: 512
            read_only: false{test_cmd_line}

          attacker:
            build:
              context: ./attacker-server
              dockerfile: Dockerfile
            image: vulscan-attacker-service
            networks:
              - vulscan_internal
            cap_drop:
              - ALL
            security_opt:
              - no-new-privileges:true
            mem_limit: 256m
            cpus: 0.5
            pids_limit: 128

        networks:
          vulscan_internal:
            driver: bridge
            internal: true
        """
    )
