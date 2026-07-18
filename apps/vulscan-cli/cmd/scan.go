package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hhh0708/911vulscan-cli/internal/checkpoint"
	"github.com/hhh0708/911vulscan-cli/internal/config"
	"github.com/hhh0708/911vulscan-cli/internal/git"
	"github.com/hhh0708/911vulscan-cli/internal/output"
	"github.com/hhh0708/911vulscan-cli/internal/python"
	"github.com/hhh0708/911vulscan-cli/internal/types"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [repository-path]",
	Short: "Scan a repository for vulnerabilities (full pipeline)",
	Long: `Scan runs the full pipeline:
  parse → app_context → reachability → enhance → detect → verify → dynamic_verify → report

This is the recommended command for most users. It produces a complete
vulnerability report with false positive elimination.

If no repository path is given, the active project is used (see: vulscan init).

Defaults: scope=reachable, verify=true, dynamic_verify=false.
Pass --dynamic-verify to enable Docker-isolated dynamic testing.

Each run gets a unique run_id. Results are written to:
  {output}/runs/{run_id}/

scan_manifest.json records the immutable ScanRequest, run_id, and config hash.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runScan,
}

var (
	scanOutput        string
	scanLanguage      string
	scanScope         string
	scanNoVerify      bool
	scanNoContext     bool
	scanNoEnhance     bool
	scanEnhanceMode   string
	scanNoReport      bool
	scanDynamicVerify bool
	scanLimit         int
	scanModel         string
	scanWorkers       int
	scanRunID         string
	scanFull          bool
	scanIncremental   bool
	scanDiffBase      string
	scanPR            int
	scanDiffScope     string
	scanFailOn        string
)

func init() {
	registerScanFlags(scanCmd)
}

// registerScanFlags wires the full scan-pipeline flag set onto cmd. Used by
// scanCmd and by the thin diffCmd wrapper so that both surfaces accept the
// same knobs.
func registerScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output root directory (default: project scan dir or temp dir). Runs land under {output}/runs/{run_id}/")
	cmd.Flags().StringVarP(&scanLanguage, "language", "l", "", "Language: python, javascript, typescript, go, c, cpp, auto")
	cmd.Flags().StringVar(&scanScope, "scope", "reachable", "Unit selection scope: all, reachable")
	cmd.Flags().BoolVar(&scanNoVerify, "no-verify", false, "Skip Stage 2 attacker simulation (enabled by default)")
	cmd.Flags().BoolVar(&scanNoContext, "no-context", false, "Skip application context generation")
	cmd.Flags().BoolVar(&scanNoEnhance, "no-enhance", false, "Skip context enhancement step")
	cmd.Flags().StringVar(&scanEnhanceMode, "enhance-mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	cmd.Flags().BoolVar(&scanNoReport, "no-report", false, "Skip report generation")
	cmd.Flags().BoolVar(&scanDynamicVerify, "dynamic-verify", false, "Enable Docker-isolated dynamic verification (off by default)")
	cmd.Flags().IntVar(&scanLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	cmd.Flags().StringVar(&scanModel, "model", "opus", "Model: opus or sonnet")
	cmd.Flags().IntVar(&scanWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	cmd.Flags().StringVar(&scanRunID, "run-id", "", "Unique run identity (default: auto-generated)")
	cmd.Flags().BoolVar(&scanFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	cmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	cmd.Flags().StringVar(&scanDiffBase, "diff-base", "", "Incremental mode: filter pipeline to units overlapping diff vs this ref (e.g. origin/main, HEAD~5)")
	cmd.Flags().IntVar(&scanPR, "pr", 0, "Incremental mode against a GitHub PR number (requires gh; mutex with --diff-base)")
	cmd.Flags().StringVar(&scanDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
	cmd.Flags().StringVar(&scanFailOn, "fail-on", "", "Exit non-zero when threshold met: candidate|confirmed|reproduced|error (default: never fail on findings)")
}

func generateRunID() string {
	ts := time.Now().UTC().Format("20060102T150405Z")
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to nanosecond entropy.
		return fmt.Sprintf("%s_%d", ts, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s_%s", ts, hex.EncodeToString(b[:]))
}

// buildScanPyArgs assembles a complete ScanRequest argv for the Python CLI.
// Every ScanRequest field is forwarded explicitly so Python never fills defaults.
func buildScanPyArgs(
	repoPath, outputRoot, runID, language, scope, enhanceMode, model string,
	noVerify, noContext, noEnhance, noReport, dynamicVerify bool,
	limit, workers int,
	manifestPath, repoName, repoURL, commitSHA string,
	failOn string,
) []string {
	pyArgs := []string{
		"scan", repoPath,
		"--output", outputRoot,
		"--run-id", runID,
		"--language", language,
		"--scope", scope,
		"--enhance-mode", enhanceMode,
		"--model", model,
		"--workers", fmt.Sprintf("%d", workers),
	}
	if noVerify {
		pyArgs = append(pyArgs, "--no-verify")
	}
	if noContext {
		pyArgs = append(pyArgs, "--no-context")
	}
	if noEnhance {
		pyArgs = append(pyArgs, "--no-enhance")
	}
	if noReport {
		pyArgs = append(pyArgs, "--no-report")
	}
	if dynamicVerify {
		pyArgs = append(pyArgs, "--dynamic-verify")
	}
	if limit > 0 {
		pyArgs = append(pyArgs, "--limit", fmt.Sprintf("%d", limit))
	}
	if manifestPath != "" {
		pyArgs = append(pyArgs, "--diff-manifest", manifestPath)
	}
	if repoName != "" {
		pyArgs = append(pyArgs, "--repo-name", repoName)
	}
	if repoURL != "" {
		pyArgs = append(pyArgs, "--repo-url", repoURL)
	}
	if commitSHA != "" {
		pyArgs = append(pyArgs, "--commit-sha", commitSHA)
	}
	if failOn != "" {
		pyArgs = append(pyArgs, "--fail-on", failOn)
	}
	return pyArgs
}

func runScan(cmd *cobra.Command, args []string) {
	if err := rejectRemovedScanFlags(cmd); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Fail-fast on missing Docker when dynamic-verify will run.
	if scanDynamicVerify {
		if err := checkDockerAvailable(); err != nil {
			output.PrintError(err.Error())
			os.Exit(2)
		}
	}

	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults if using project context
	outputRoot := scanOutput
	language := scanLanguage
	if ctx != nil {
		if outputRoot == "" {
			outputRoot = ctx.ScanDir
		}
		if language == "" {
			language = ctx.Language
		}
	}
	if language == "" {
		language = "auto"
	}
	if outputRoot == "" {
		tmp, err := os.MkdirTemp("", "911vulscan_")
		if err != nil {
			output.PrintError(fmt.Sprintf("failed to create temp output dir: %s", err))
			os.Exit(2)
		}
		outputRoot = tmp
	}
	outputRoot, err = filepath.Abs(outputRoot)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Decide full vs incremental, honoring init's running meta.json if
	// present (init was just run for this commit and recorded the choice).
	decision, err := resolveScanMode(ctx, repoPath)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Allocate run identity up front so diff/checkpoint paths use run_dir.
	runID := scanRunID
	if runID == "" {
		runID = generateRunID()
	} else if err := config.ValidateRunID(runID); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	runDir := filepath.Join(outputRoot, "runs", runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		output.PrintError(fmt.Sprintf("failed to create run dir: %s", err))
		os.Exit(2)
	}

	// Build the diff manifest inside the current run_dir.
	manifestOpts := diffOpts{}
	if decision.Kind == config.ScanKindDiff {
		manifestOpts.base = decision.Base
		manifestOpts.scope = decision.Scope
	}
	manifestPath, err := prepareDiffManifest(repoPath, runDir, manifestOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Checkpoints live under the current run_dir (new runs start empty).
	steps := []string{"enhance", "analyze", "verify"}
	for _, step := range steps {
		if cpInfo := checkpoint.DetectViaPython(rt.Path, runDir, step); cpInfo != nil {
			if !checkpoint.PromptResume(cpInfo, step, quiet) {
				_ = checkpoint.Clean(cpInfo.Dir)
			}
		}
	}

	repoName, repoURL, commitSHA := "", "", ""
	if ctx != nil && ctx.Project != nil {
		repoName = ctx.Project.Name
		repoURL = ctx.Project.RepoURL
		commitSHA = ctx.Project.CommitSHA
	}

	// Fully construct ScanRequest argv — no omitted defaults.
	pyArgs := buildScanPyArgs(
		repoPath, outputRoot, runID, language, scanScope, scanEnhanceMode, scanModel,
		scanNoVerify, scanNoContext, scanNoEnhance, scanNoReport, scanDynamicVerify,
		scanLimit, scanWorkers,
		manifestPath, repoName, repoURL, commitSHA,
		scanFailOn,
	)

	if !quiet {
		fmt.Fprintf(os.Stderr, "Run ID: %s\nRun dir: %s\n", runID, runDir)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey())
	if err != nil {
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
		output.PrintError(err.Error())
		os.Exit(2)
	}

	switch result.Envelope.Status {
	case "interrupted":
		finalizeScanMetaIfProject(ctx, config.ScanStatusInterrupted)
	case "completed", "partial", "success":
		finalizeScanMetaIfProject(ctx, config.ScanStatusSuccess)
	default:
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
	}

	if result.Envelope.Status == "interrupted" {
		os.Exit(130)
	} else if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if types.EnvelopeSucceeded(result.Envelope.Status) {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintScanSummaryV2(data)
		} else {
			// Unexpected payload shape — don't leave the user with no output.
			output.PrintJSON(result.Envelope)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(exitCodeForResult(result))
}

// rejectRemovedScanFlags fails fast when legacy flags appear on argv.
func rejectRemovedScanFlags(cmd *cobra.Command) error {
	removed := map[string]string{
		"level":                           "--level has been removed; use --scope all|reachable",
		"real-world":                      "--real-world has been removed from the production pipeline",
		"llm-reachability":                "--llm-reachability has been removed; use --scope",
		"llm-reachability-max-code-bytes": "--llm-reachability-max-code-bytes has been removed",
		"skip-dynamic-test":               "--skip-dynamic-test has been removed; dynamic verify is off by default (pass --dynamic-verify to enable)",
		"dynamic-test":                    "--dynamic-test has been renamed to --dynamic-verify",
		"verify":                          "--verify is now the default; use --no-verify to disable",
		"backoff":                         "--backoff is no longer a scan ScanRequest field (rate-limit backoff is an internal constant)",
	}
	for name, msg := range removed {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("%s", msg)
		}
	}
	for _, arg := range os.Args[1:] {
		key := arg
		if i := indexByte(arg, '='); i >= 0 {
			key = arg[:i]
		}
		switch key {
		case "--level":
			return fmt.Errorf("%s", removed["level"])
		case "--real-world":
			return fmt.Errorf("%s", removed["real-world"])
		case "--llm-reachability":
			return fmt.Errorf("%s", removed["llm-reachability"])
		case "--llm-reachability-max-code-bytes":
			return fmt.Errorf("%s", removed["llm-reachability-max-code-bytes"])
		case "--skip-dynamic-test":
			return fmt.Errorf("%s", removed["skip-dynamic-test"])
		case "--dynamic-test":
			return fmt.Errorf("%s", removed["dynamic-test"])
		case "--backoff":
			if cmd.Name() == "scan" || cmd.Name() == "diff" {
				return fmt.Errorf("%s", removed["backoff"])
			}
		case "--verify":
			if cmd.Name() == "scan" || cmd.Name() == "diff" {
				return fmt.Errorf("%s", removed["verify"])
			}
		}
	}
	return nil
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// finalizeScanMetaIfProject updates the scan-run meta.json with a terminal
// status when the scan ran against a known project. Ad-hoc scans without
// project context have no meta.json and are silently skipped.
func finalizeScanMetaIfProject(ctx *projectContext, status string) {
	if ctx == nil || ctx.Project == nil {
		return
	}
	if err := config.FinalizeScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, status); err != nil {
		output.PrintWarning(fmt.Sprintf("Failed to update scan meta: %s", err))
	}
}

// resolveScanMode produces the modeDecision for this scan run. Honors a
// running meta.json from a recent `vulscan init` (so the user is not
// re-prompted), otherwise calls selectMode with the scan flags.
//
// When running against a project, also writes meta.json status=running
// reflecting the decision so step verbs and finalizeScanMetaIfProject
// have something to read/update.
func resolveScanMode(ctx *projectContext, repoPath string) (modeDecision, error) {
	flagsPassed := scanFull || scanIncremental || scanDiffBase != "" || scanPR > 0

	// Reuse init's pending decision when no flags override it.
	if !flagsPassed && ctx != nil && ctx.Project != nil {
		existing, err := config.LoadScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort)
		if err == nil && existing.Status == config.ScanStatusRunning {
			return modeDecision{Kind: existing.Kind, Base: existing.Base, Scope: existing.Scope}, nil
		}
	}

	projectName := ""
	if ctx != nil && ctx.Project != nil {
		projectName = ctx.Project.Name
	}

	decision, err := selectMode(modeOpts{
		full:        scanFull,
		incremental: scanIncremental,
		diffBase:    scanDiffBase,
		pr:          scanPR,
		scope:       scanDiffScope,
		projectName: projectName,
		repoPath:    repoPath,
	})
	if err != nil {
		return modeDecision{}, err
	}

	// Record the decision in meta.json status=running if we have a project.
	// finalizeScanMetaIfProject will flip it terminal when the pipeline ends.
	if ctx != nil && ctx.Project != nil {
		meta := config.NewScanMeta(
			decision.Kind,
			ctx.Project.CommitSHA,
			git.CurrentBranch(repoPath),
			ctx.Project.Language,
		)
		meta.Base = decision.Base
		meta.Scope = decision.Scope
		if err := config.SaveScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, meta); err != nil {
			output.PrintWarning(fmt.Sprintf("Failed to write scan meta: %s", err))
		}
	}

	return decision, nil
}
