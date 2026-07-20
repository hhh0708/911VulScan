# Dynamic Verification — Production Status

**Status: NOT production-ready** until the Docker dynamic E2E suite
(`python -m pytest tests/test_phase12_docker_e2e.py -q` with
`VULSCAN_REQUIRE_DOCKER_E2E=1`) succeeds on a recorded commit.

## Gate criteria

1. Base images exist locally; builds use `--network=none --pull=false` (no auto-pull).
2. **Python, JavaScript, Go, and C/C++** harnesses must each perform a **real
   target call** and finish with ``decision=reproduced`` (strict
   `TARGET_CALL_BEGIN` identity: `test_id`, `finding_id`, `unit_id`,
   `entrypoint`, `attempt_id`).
3. **Go/C must not pass on arbitrary `build_error` / "reliable blocked".**
   A successful reproduced call is required for the positive language cases.
4. **Missing-symbol blocked** is an **independent negative case** only — it
   must actually run a build and assert a clear blocked/inconclusive reason;
   it does not substitute for the Go/C reproduced gates.
5. **not_reproduced** is an independent negative case: real target call plus
   completed negative oracle.
6. Image digest and base image digest are captured by the executor **before**
   image cleanup.
7. Local environments without Docker must `pytest.skip` — never count as passed.
8. In the GitHub Docker job (`VULSCAN_REQUIRE_DOCKER_E2E=1`), skips are failures.
9. Report generation (HTML/CSV/Markdown/disclosure) requires a validated
   FinalScanArtifact + matching `run_artifact_manifest.json` hashes.

## After a successful workflow run, record here

| Field | Value |
|-------|-------|
| workflow run URL | _(pending)_ |
| tested commit SHA | _(pending)_ |
| python base digest | _(pending)_ |
| node base digest | _(pending)_ |
| golang base digest | _(pending)_ |
| gcc base digest | _(pending)_ |
| Python result | _(pending)_ |
| JavaScript result | _(pending)_ |
| Go result | _(pending)_ |
| C/C++ result | _(pending)_ |
| test timestamp (UTC) | _(pending)_ |

Do not claim production readiness until this table is filled from CI.
