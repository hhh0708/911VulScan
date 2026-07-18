"""Analysis metrics for final scan artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class AnalysisMetrics:
    """Per-stage analysis counters (unit / finding level)."""

    total_units: int = 0
    reachable: int = 0
    unreachable: int = 0
    unknown_reachability: int = 0
    stage1_candidates: int = 0
    stage1_no_finding: int = 0
    stage1_inconclusive: int = 0
    stage1_errors: int = 0
    stage2_confirmed: int = 0
    stage2_rejected: int = 0
    stage2_inconclusive: int = 0
    stage2_failed: int = 0
    dynamic_reproduced: int = 0
    dynamic_not_reproduced: int = 0
    dynamic_inconclusive: int = 0
    dynamic_failed: int = 0
    dynamic_blocked: int = 0
    dynamic_skipped: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def validate_invariants(self, *, reachability_partial: bool = False) -> list[str]:
        """Return list of invariant violation messages."""
        errors: list[str] = []

        if self.total_units > 0 and not reachability_partial:
            reach_sum = self.reachable + self.unreachable + self.unknown_reachability
            if reach_sum != self.total_units:
                errors.append(
                    f"reachability sum {reach_sum} != total_units {self.total_units}"
                )

        stage1_sum = (
            self.stage1_candidates
            + self.stage1_no_finding
            + self.stage1_inconclusive
            + self.stage1_errors
        )
        if stage1_sum > self.total_units:
            errors.append(
                f"stage1 counts sum {stage1_sum} exceeds total_units {self.total_units}"
            )

        return errors
