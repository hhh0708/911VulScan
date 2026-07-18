// Package report provides HTML report generation from pre-computed data.
package report

import (
	"fmt"
	"html"
	"html/template"
	"strings"
)

// ReportData holds all pre-computed data needed to render the HTML overview report.
// This struct maps 1:1 to the JSON output of the Python `report-data` subcommand.
type ReportData struct {
	Title             string         `json:"title"`
	Timestamp         string         `json:"timestamp"`
	RepoName          string         `json:"repo_name"`
	CommitSHA         string         `json:"commit_sha"`
	Language          string         `json:"language"`
	RepoURL           string         `json:"repo_url"`
	TotalDurationS    float64        `json:"total_duration_seconds"`
	TotalCostUSD      float64        `json:"total_cost_usd"`
	Stats             Stats          `json:"stats"`
	UnitChart         ChartData      `json:"unit_chart"`
	FileChart         ChartData      `json:"file_chart"`
	RemediationHTML   string         `json:"remediation_html"`
	Findings          []Finding      `json:"findings"`
	FindingsByVerdict []FindingGroup `json:"findings_by_verdict"`
	StepReports       []StepReport   `json:"step_reports"`
	Categories        []Category     `json:"categories"`
	Diff              *DiffInfo      `json:"diff,omitempty"`
}

// DiffInfo carries the incremental-scan range info to the report templates.
// Nil for full scans. Mirrors the "diff" block on pipeline_output.json,
// trimmed to the fields the templates actually render.
type DiffInfo struct {
	Mode             string `json:"mode"` // "incremental"
	BaseSHA          string `json:"base_sha"`
	HeadSHA          string `json:"head_sha"`
	Scope            string `json:"scope"`
	UnitsInDiff      int    `json:"units_in_diff"`
	UnitsTotalParsed int    `json:"units_total_parsed"`
	ChangedFiles     int    `json:"changed_files"`
	PRNumber         int    `json:"pr_number,omitempty"`
}

// IsIncremental reports whether this report is for an incremental scan.
// Templates check this to decide between the "full" and "incremental"
// header renderings.
func (d ReportData) IsIncremental() bool {
	return d.Diff != nil && d.Diff.Mode == "incremental"
}

// ShortBaseSHA returns the first 8 characters of the diff base SHA, or "".
func (d ReportData) ShortBaseSHA() string {
	if d.Diff == nil {
		return ""
	}
	if len(d.Diff.BaseSHA) > 8 {
		return d.Diff.BaseSHA[:8]
	}
	return d.Diff.BaseSHA
}

// ShortHeadSHA returns the first 8 characters of the diff head SHA, or "".
func (d ReportData) ShortHeadSHA() string {
	if d.Diff == nil {
		return ""
	}
	if len(d.Diff.HeadSHA) > 8 {
		return d.Diff.HeadSHA[:8]
	}
	return d.Diff.HeadSHA
}

// DiffRange returns the git-style "<base8>..<head8>" string, or "".
func (d ReportData) DiffRange() string {
	if d.Diff == nil {
		return ""
	}
	return d.ShortBaseSHA() + ".." + d.ShortHeadSHA()
}

// SafeRemediation returns the remediation text as safe template.HTML for
// the report templates. The content is LLM-generated from analyzed (and
// potentially hostile) source code, so it must never be rendered raw: the
// text is HTML-escaped first, then newlines become <br> for readability.
func (d ReportData) SafeRemediation() template.HTML {
	escaped := html.EscapeString(d.RemediationHTML)
	return template.HTML(strings.ReplaceAll(escaped, "\n", "<br>"))
}

// FormatDuration returns TotalDurationS as a human-readable string
// like "1d 2h 3m 4s", omitting leading zero components.
func (d ReportData) FormatDuration() string {
	total := int(d.TotalDurationS)
	if total <= 0 {
		return ""
	}
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, " ")
}

// FormatTotalCost returns TotalCostUSD as "$X.XX", or "-" if zero.
func (d ReportData) FormatTotalCost() string {
	if d.TotalCostUSD <= 0 {
		return "-"
	}
	return fmt.Sprintf("$%.2f", d.TotalCostUSD)
}

// ShortCommit returns the first 10 characters of CommitSHA, or empty.
func (d ReportData) ShortCommit() string {
	if len(d.CommitSHA) > 10 {
		return d.CommitSHA[:10]
	}
	return d.CommitSHA
}

// FileURL constructs a browseable URL for a file path in the repo.
// Returns empty string if repo URL or commit SHA is missing.
func (d ReportData) FileURL(filePath string) string {
	if d.RepoURL == "" || d.CommitSHA == "" {
		return ""
	}
	base := strings.TrimRight(d.RepoURL, "/")
	base = strings.TrimSuffix(base, ".git")
	return base + "/blob/" + d.CommitSHA + "/" + filePath
}

// HasStepReports returns true if there are step reports to display.
func (d ReportData) HasStepReports() bool {
	return len(d.StepReports) > 0
}

// HasFindings returns true if there are findings to display.
func (d ReportData) HasFindings() bool {
	return len(d.Findings) > 0
}

// HasFindingGroups returns true if there are grouped findings to display.
func (d ReportData) HasFindingGroups() bool {
	return len(d.FindingsByVerdict) > 0
}

// Stats holds the summary statistics for the report header cards.
// Counts are sourced from FinalScanArtifact.metrics and finding buckets.
type Stats struct {
	TotalUnits   int `json:"total_units"`
	TotalFiles   int `json:"total_files"`
	Reproduced   int `json:"reproduced"`
	Confirmed    int `json:"confirmed"`
	Candidates   int `json:"candidates"`
	Rejected     int `json:"rejected"`
	Inconclusive int `json:"inconclusive"`
	Errors       int `json:"errors"`
}

// InconclusiveOrErrors returns the combined inconclusive and error count for summary cards.
func (s Stats) InconclusiveOrErrors() int {
	return s.Inconclusive + s.Errors
}

// ChartData holds the data for a Chart.js pie chart.
type ChartData struct {
	Labels []string `json:"labels"`
	Data   []int    `json:"data"`
	Colors []string `json:"colors"`
}

// FindingGroup holds findings grouped by final_state for collapsible sections.
// Verdict holds the final_state key; VerdictLabel is the display name.
type FindingGroup struct {
	Verdict       string            `json:"verdict"`
	VerdictLabel  string            `json:"verdict_label"`
	VerdictColor  string            `json:"verdict_color"`
	Count         int               `json:"count"`
	OpenByDefault bool              `json:"open_by_default"`
	Findings      []Finding         `json:"findings"`
	Subgroups     []FindingSubgroup `json:"subgroups"`
	HasSubgroups  bool              `json:"has_subgroups"`
}

// FindingSubgroup holds findings within a group, sub-grouped when needed.
type FindingSubgroup struct {
	Label    string    `json:"label"`
	Findings []Finding `json:"findings"`
}

// Finding represents a single finding row in the report table.
// Verdict holds the final_state key for template compatibility.
type Finding struct {
	Number             int    `json:"number"`
	Verdict            string `json:"verdict"`
	FinalState         string `json:"final_state"`
	VerdictLabel       string `json:"verdict_label"`
	VerdictColor       string `json:"verdict_color"`
	File               string `json:"file"`
	Function           string `json:"function"`
	AttackVector       string `json:"attack_vector"`
	Analysis           string `json:"analysis"`
	DynamicTestStatus  string `json:"dynamic_test_status"`
	DynamicTestDetails string `json:"dynamic_test_details"`
}

// HasDynamicTest returns true if this finding has dynamic test results.
func (f Finding) HasDynamicTest() bool {
	return f.DynamicTestStatus != ""
}

// DynamicTestColor returns a color for the dynamic verification status badge.
func (f Finding) DynamicTestColor() string {
	switch f.DynamicTestStatus {
	case "reproduced":
		return "#dc3545"
	case "not_reproduced":
		return "#28a745"
	case "inconclusive":
		return "#fd7e14"
	case "failed", "error":
		return "#6c757d"
	case "blocked", "skipped":
		return "#6c757d"
	default:
		return "#6c757d"
	}
}

// DisplayLabel returns the human-readable final_state label when present.
func (f Finding) DisplayLabel() string {
	if f.VerdictLabel != "" {
		return f.VerdictLabel
	}
	return f.Verdict
}

// IsHighSeverity returns true for high-priority final_state values,
// used to auto-open their <details> accordion in the HTML report.
func (f Finding) IsHighSeverity() bool {
	switch f.FinalState {
	case "reproduced", "confirmed_not_dynamically_tested", "confirmed_not_reproduced", "candidate":
		return true
	default:
		if f.FinalState == "" {
			switch f.Verdict {
			case "reproduced", "confirmed_not_dynamically_tested", "confirmed_not_reproduced", "candidate":
				return true
			}
		}
		return false
	}
}

// StepReport holds display-ready data for a pipeline step.
type StepReport struct {
	Step      string `json:"step"`
	Duration  string `json:"duration"`
	Cost      string `json:"cost"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// StatusColor returns a Tailwind text color class based on step status.
func (s StepReport) StatusColor() string {
	switch s.Status {
	case "success":
		return "text-green-400"
	case "error":
		return "text-red-400"
	default:
		return "text-gray-400"
	}
}

// GroupLabel returns the display label for a finding group.
func (g FindingGroup) GroupLabel() string {
	if g.VerdictLabel != "" {
		return g.VerdictLabel
	}
	return g.Verdict
}

// Category holds a final_state category description for the legend table.
type Category struct {
	Key         string `json:"key"`
	Verdict     string `json:"verdict"`
	Color       string `json:"color"`
	Description string `json:"description"`
}
