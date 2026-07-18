package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/hhh0708/911vulscan-cli/internal/output"
	"github.com/hhh0708/911vulscan-cli/internal/python"
	"github.com/hhh0708/911vulscan-cli/internal/types"
	"github.com/spf13/cobra"
)

var parseCmd = &cobra.Command{
	Use:   "parse [repository-path]",
	Short: "Extract code units from a repository",
	Long: `Parse extracts analyzable code units from a repository.

The output is a JSON dataset that can be fed into the analyze command.
Supports Python, JavaScript/TypeScript, Go, and C/C++ repositories.

If no repository path is given, the active project is used (see: vulscan init).`,
	Args: cobra.MaximumNArgs(1),
	Run:  runParse,
}

var (
	parseOutput    string
	parseLanguage  string
	parseScope     string
	parseDiffBase  string
	parsePR        int
	parseDiffScope string
)

func init() {
	parseCmd.Flags().StringVarP(&parseOutput, "output", "o", "", "Output directory (default: project scan dir)")
	parseCmd.Flags().StringVarP(&parseLanguage, "language", "l", "", "Language: python, javascript, typescript, go, c, cpp, auto")
	parseCmd.Flags().StringVar(&parseScope, "scope", "reachable", "Unit selection scope: all, reachable")
	parseCmd.Flags().StringVar(&parseDiffBase, "diff-base", "", "Incremental mode: tag units overlapping diff vs this ref")
	parseCmd.Flags().IntVar(&parsePR, "pr", 0, "Incremental mode against a GitHub PR number (mutex with --diff-base)")
	parseCmd.Flags().StringVar(&parseDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
}

// buildParsePyArgs assembles the argv passed to the Python `vulscan parse`
// subprocess. Defaults that match the Python CLI (language=auto,
// scope=reachable) are omitted so the Python side stays in charge of the
// canonical default value.
func buildParsePyArgs(repoPath, output, datasetName, language, scope, manifestPath string) []string {
	pyArgs := []string{"parse", repoPath, "--output", output}
	if datasetName != "" {
		pyArgs = append(pyArgs, "--name", datasetName)
	}
	if language != "auto" {
		pyArgs = append(pyArgs, "--language", language)
	}
	if scope != "reachable" {
		pyArgs = append(pyArgs, "--scope", scope)
	}
	if manifestPath != "" {
		pyArgs = append(pyArgs, "--diff-manifest", manifestPath)
	}
	return pyArgs
}

func runParse(cmd *cobra.Command, args []string) {
	for _, arg := range os.Args[1:] {
		key := arg
		if i := strings.IndexByte(arg, '='); i >= 0 {
			key = arg[:i]
		}
		if key == "--level" {
			output.PrintError("--level has been removed; use --scope all|reachable")
			os.Exit(2)
		}
	}

	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if parseOutput == "" {
			parseOutput = ctx.ScanDir
		}
		if parseLanguage == "" {
			parseLanguage = ctx.Language
		}
	}
	if parseLanguage == "" {
		parseLanguage = "auto"
	}
	if parseOutput == "" {
		output.PrintError("--output is required (or use vulscan init to set up a project)")
		os.Exit(2)
	}

	switch parseScope {
	case "all", "reachable":
	default:
		output.PrintError(fmt.Sprintf("invalid --scope %q (expected all|reachable)", parseScope))
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	stepOpts, err := resolveStepDiffOpts(ctx, parseDiffBase, parsePR, parseDiffScope)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	manifestPath, err := prepareDiffManifest(repoPath, parseOutput, stepOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Construct dataset name from project metadata: org-repo-shortSHA
	var datasetName string
	if ctx != nil && ctx.Project != nil {
		slug := strings.ReplaceAll(ctx.Project.Name, "/", "-")
		if ctx.Project.CommitSHAShort != "" {
			datasetName = slug + "-" + ctx.Project.CommitSHAShort
		} else {
			datasetName = slug
		}
	}

	pyArgs := buildParsePyArgs(repoPath, parseOutput, datasetName, parseLanguage, parseScope, manifestPath)

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey())
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if types.EnvelopeSucceeded(result.Envelope.Status) {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintParseSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(exitCodeForResult(result))
}
