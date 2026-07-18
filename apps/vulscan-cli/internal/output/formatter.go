// Package output handles terminal output formatting.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/hhh0708/911vulscan-cli/internal/types"
)

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	cyan   = color.New(color.FgCyan)
	dim    = color.New(color.Faint)
)

// PrintJSON outputs the raw JSON envelope to stdout.
func PrintJSON(envelope types.Envelope) {
	data, _ := json.MarshalIndent(envelope, "", "  ")
	fmt.Println(string(data))
}

// PrintError outputs an error message to stderr.
func PrintError(msg string) {
	red.Fprintf(os.Stderr, "Error: ")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintErrors outputs multiple error messages to stderr.
func PrintErrors(errors []string) {
	for _, e := range errors {
		PrintError(e)
	}
}

// PrintSuccess outputs a success message.
func PrintSuccess(msg string) {
	green.Print("✓ ")
	fmt.Println(msg)
}

// PrintWarning outputs a warning message to stderr.
func PrintWarning(msg string) {
	yellow.Fprintf(os.Stderr, "Warning: ")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintHeader outputs a section header.
func PrintHeader(msg string) {
	fmt.Println()
	bold.Println(msg)
	fmt.Println(strings.Repeat("─", len(msg)))
}

// PrintKeyValue outputs a key-value pair.
func PrintKeyValue(key, value string) {
	cyan.Printf("  %s: ", key)
	fmt.Println(value)
}

// PrintParseSummary outputs a formatted summary of parse results.
func PrintParseSummary(data map[string]any) {
	PrintHeader("Parse Results")
	if lang, ok := data["language"].(string); ok {
		PrintKeyValue("Language", lang)
	}
	if scope, ok := data["scope"].(string); ok {
		PrintKeyValue("Scope", scope)
	}
	if units := intFromAny(data["units_count"]); units > 0 {
		PrintKeyValue("Units extracted", fmt.Sprintf("%d", units))
	}
	if path, ok := data["dataset_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintAnalyzeSummary outputs a formatted summary of analysis results.
func PrintAnalyzeSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("Analysis Results")
	total := intFromAny(metrics["total_units"])
	if total == 0 {
		total = intFromAny(metrics["total"])
	}
	candidates := intFromAny(metrics["stage1_candidates"])
	noFinding := intFromAny(metrics["stage1_no_finding"])
	inconclusive := intFromAny(metrics["stage1_inconclusive"])
	errors := intFromAny(metrics["stage1_errors"])

	PrintKeyValue("Total units", fmt.Sprintf("%d", total))
	if candidates > 0 {
		yellow.Printf("  Stage 1 candidates: %d\n", candidates)
	}
	PrintKeyValue("No finding", fmt.Sprintf("%d", noFinding))
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if errors > 0 {
		yellow.Printf("  Errors: %d\n", errors)
	}

	if path, ok := data["results_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintReportSummary outputs a formatted summary of report generation.
func PrintReportSummary(data map[string]any) {
	PrintHeader("Report Generated")
	if format, ok := data["format"].(string); ok && format != "" {
		PrintKeyValue("Format", format)
	}
	if path, ok := data["output_path"].(string); ok && path != "" {
		PrintKeyValue("Output", path)
	}
	if path, ok := data["reskin_path"].(string); ok && path != "" {
		PrintKeyValue("Reskin", path)
	}
	if usage, ok := data["usage"].(map[string]any); ok {
		cost := floatFromAny(usage["total_cost_usd"])
		if cost > 0 {
			currency := stringFromAny(usage["cost_currency"])
			PrintKeyValue("Cost", formatCost(cost, currency))
		}
	}
	fmt.Println()
}

// PrintEnhanceSummary outputs a formatted summary of enhancement results.
func PrintEnhanceSummary(data map[string]any) {
	PrintHeader("Enhancement Results")

	units := intFromAny(data["units_enhanced"])
	errors := intFromAny(data["error_count"])
	PrintKeyValue("Units enhanced", fmt.Sprintf("%d", units))
	if errors > 0 {
		yellow.Printf("  Errors: %d\n", errors)
	}

	if path, ok := data["enhanced_dataset_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintVerifySummary outputs a formatted summary of verification results.
func PrintVerifySummary(data map[string]any) {
	PrintHeader("Verification Results (Stage 2)")

	input := intFromAny(data["candidates_input"])
	if input == 0 {
		input = intFromAny(data["findings_input"])
	}
	attempted := intFromAny(data["attempted"])
	if attempted == 0 {
		attempted = intFromAny(data["findings_verified"])
	}
	confirmed := intFromAny(data["confirmed"])
	rejected := intFromAny(data["rejected"])
	inconclusive := intFromAny(data["inconclusive"])
	failed := intFromAny(data["failed"])
	skipped := intFromAny(data["skipped"])

	PrintKeyValue("Candidates input", fmt.Sprintf("%d", input))
	PrintKeyValue("Attempted", fmt.Sprintf("%d", attempted))
	if skipped > 0 {
		PrintKeyValue("Skipped", fmt.Sprintf("%d", skipped))
	}

	if confirmed > 0 {
		red.Printf("  Confirmed: %d\n", confirmed)
	}
	if rejected > 0 {
		green.Printf("  Rejected: %d\n", rejected)
	}
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if failed > 0 {
		yellow.Printf("  Failed: %d\n", failed)
	}

	fmt.Println()
	if confirmed > 0 {
		red.Printf("⚠ %d confirmed vulnerabilit", confirmed)
		if confirmed == 1 {
			red.Println("y")
		} else {
			red.Println("ies")
		}
	} else {
		green.Println("✓ No confirmed vulnerabilities")
	}

	if path, ok := data["verified_results_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintDynamicTestSummary outputs a formatted summary of dynamic test results.
func PrintDynamicTestSummary(data map[string]any) {
	PrintHeader("Dynamic Test Results")

	candidates := intFromAny(data["candidates_input"])
	attempted := intFromAny(data["attempted"])
	succeeded := intFromAny(data["succeeded"])
	failed := intFromAny(data["failed"])
	blocked := intFromAny(data["blocked"])
	skipped := intFromAny(data["skipped"])
	reproduced := intFromAny(data["reproduced"])
	notReproduced := intFromAny(data["not_reproduced"])
	inconclusive := intFromAny(data["inconclusive"])

	PrintKeyValue("Candidates input", fmt.Sprintf("%d", candidates))
	PrintKeyValue("Attempted", fmt.Sprintf("%d", attempted))
	if succeeded > 0 {
		PrintKeyValue("Succeeded", fmt.Sprintf("%d", succeeded))
	}

	if reproduced > 0 {
		red.Printf("  Reproduced: %d\n", reproduced)
	}
	if notReproduced > 0 {
		green.Printf("  Not reproduced: %d\n", notReproduced)
	}
	if blocked > 0 {
		yellow.Printf("  Blocked: %d\n", blocked)
	}
	if skipped > 0 {
		yellow.Printf("  Skipped: %d\n", skipped)
	}
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if failed > 0 {
		red.Printf("  Failed: %d\n", failed)
	}

	if path, ok := data["results_json_path"].(string); ok {
		PrintKeyValue("Results", path)
	}
	fmt.Println()
}

// PrintBuildOutputSummary outputs a formatted summary of pipeline output generation.
func PrintBuildOutputSummary(data map[string]any) {
	PrintHeader("Pipeline Output")

	findings := intFromAny(data["findings_count"])
	PrintKeyValue("Findings included", fmt.Sprintf("%d", findings))

	if path, ok := data["pipeline_output_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintScanSummaryV2 outputs a formatted summary of scan results using Phase 11 metrics.
func PrintScanSummaryV2(data map[string]any) {
	printScanMetricsSummary(data)
}

func printScanMetricsSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("Scan Results")

	if diff, ok := data["diff"].(map[string]any); ok && diff != nil {
		if mode, _ := diff["mode"].(string); mode == "incremental" {
			base := shortSHA8(diff["base_sha"])
			head := shortSHA8(diff["head_sha"])
			unitsIn := intFromAny(diff["units_in_diff"])
			unitsTotal := intFromAny(diff["units_total_parsed"])
			modeLine := fmt.Sprintf("Incremental (%s..%s, %d/%d units)", base, head, unitsIn, unitsTotal)
			PrintKeyValue("Mode", modeLine)
		} else {
			PrintKeyValue("Mode", "Full")
		}
	}

	total := intFromAny(metrics["total_units"])
	if total == 0 {
		total = intFromAny(metrics["total"])
	}
	stage2Confirmed := intFromAny(metrics["stage2_confirmed"])
	stage1Candidates := intFromAny(metrics["stage1_candidates"])
	dynamicReproduced := intFromAny(metrics["dynamic_reproduced"])
	stage2Rejected := intFromAny(metrics["stage2_rejected"])
	stage1Inconclusive := intFromAny(metrics["stage1_inconclusive"])
	stage2Inconclusive := intFromAny(metrics["stage2_inconclusive"])
	stage1Errors := intFromAny(metrics["stage1_errors"])
	stage2Failed := intFromAny(metrics["stage2_failed"])
	dynamicFailed := intFromAny(metrics["dynamic_failed"])

	PrintKeyValue("Total units analyzed", fmt.Sprintf("%d", total))

	combined := stage2Confirmed + dynamicReproduced
	if combined > 0 {
		red.Printf("  Confirmed / reproduced: %d\n", combined)
	} else {
		green.Printf("  Confirmed / reproduced: 0\n")
	}
	if stage1Candidates > 0 {
		yellow.Printf("  Stage 1 candidates: %d\n", stage1Candidates)
	}
	if stage2Rejected > 0 {
		PrintKeyValue("Stage 2 rejected", fmt.Sprintf("%d", stage2Rejected))
	}
	incTotal := stage1Inconclusive + stage2Inconclusive
	if incTotal > 0 {
		yellow.Printf("  Inconclusive: %d\n", incTotal)
	}
	errTotal := stage1Errors + stage2Failed + dynamicFailed
	if errTotal > 0 {
		yellow.Printf("  Errors: %d\n", errTotal)
	}

	if usage, ok := data["usage"].(map[string]any); ok {
		PrintHeader("Usage")
		cost := floatFromAny(usage["total_cost_usd"])
		currency := stringFromAny(usage["cost_currency"])
		inputTokens := intFromAny(usage["total_input_tokens"])
		outputTokens := intFromAny(usage["total_output_tokens"])

		PrintKeyValue("Cost", formatCost(cost, currency))
		PrintKeyValue("Tokens", fmt.Sprintf("%d input / %d output", inputTokens, outputTokens))
	}

	PrintHeader("Output Files")
	if dir, ok := data["output_dir"].(string); ok {
		PrintKeyValue("Directory", dir)
	}
	if path, ok := data["pipeline_output_path"].(string); ok && path != "" {
		PrintKeyValue("Pipeline output", path)
	}
	if path, ok := data["summary_path"].(string); ok && path != "" {
		PrintKeyValue("Summary report", path)
	}

	if skipped, ok := data["skipped_steps"].([]any); ok && len(skipped) > 0 {
		names := make([]string, 0, len(skipped))
		for _, s := range skipped {
			if name, ok := s.(string); ok {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			dim.Printf("  Skipped: %s\n", strings.Join(names, ", "))
		}
	}

	fmt.Println()

	if combined > 0 {
		red.Printf("⚠ Found %d vulnerabilit", combined)
		if combined == 1 {
			red.Println("y")
		} else {
			red.Println("ies")
		}
	} else {
		green.Println("✓ No vulnerabilities found")
	}
}

// PrintVersion outputs version info.
func PrintVersion(version, goVersion, pythonVersion string) {
	bold.Printf("vulscan ")
	fmt.Println(version)
	dim.Printf("  Go:     %s\n", goVersion)
	if pythonVersion != "" {
		dim.Printf("  Python: %s\n", pythonVersion)
	}
}

// intFromAny extracts an int from a JSON-decoded any value (which is float64).
func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// shortSHA8 returns the first 8 characters of a SHA from a JSON-decoded
// string field. Returns "?" for missing/empty input so the rendered Mode
// line never looks malformed.
func shortSHA8(v any) string {
	s, _ := v.(string)
	if len(s) >= 8 {
		return s[:8]
	}
	if s == "" {
		return "?"
	}
	return s
}

// floatFromAny extracts a float64 from a JSON-decoded any value.
func floatFromAny(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		return 0
	}
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	if s == "" {
		return "USD"
	}
	return s
}

func formatCost(amount float64, currency string) string {
	switch currency {
	case "CNY":
		if amount < 0.01 {
			return fmt.Sprintf("¥%.4f", amount)
		}
		if amount < 10 {
			return fmt.Sprintf("¥%.2f", amount)
		}
		return fmt.Sprintf("¥%.2f", amount)
	default:
		if amount < 0.01 {
			return fmt.Sprintf("$%.4f", amount)
		}
		if amount < 10 {
			return fmt.Sprintf("$%.2f", amount)
		}
		return fmt.Sprintf("$%.2f", amount)
	}
}
