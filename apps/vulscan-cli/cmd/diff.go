package cmd

import (
	"os"

	"github.com/hhh0708/911vulscan-cli/internal/output"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [repository-path]",
	Short: "Scan only the code changed vs a base ref or GitHub PR",
	Long: `Diff runs the full scan pipeline but filters to units whose bodies
overlap a git diff hunk. One of --diff-base or --pr is required.

Examples:
  vulscan diff --diff-base origin/main
  vulscan diff --pr 123
  vulscan diff --diff-base HEAD~5 --diff-scope callers --dynamic-verify

All scan flags (--scope, --workers, --no-verify, etc.) work the same here.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if scanDiffBase == "" && scanPR == 0 {
			output.PrintError("vulscan diff requires --diff-base <ref> or --pr <N>")
			os.Exit(2)
		}
		runScan(cmd, args)
	},
}

func init() {
	registerScanFlags(diffCmd)
}
