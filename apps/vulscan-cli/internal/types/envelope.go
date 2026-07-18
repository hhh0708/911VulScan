// Package types defines the JSON structures returned by the Python CLI.
package types

// Envelope is the top-level JSON response from `python -m vulscan`.
// Every command returns this canonical shape (schema_version 1.0).
type Envelope struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"` // completed|partial|failed|interrupted
	RunID         string   `json:"run_id,omitempty"`
	Stage         string   `json:"stage,omitempty"`
	Data          any      `json:"data"`
	Metrics       any      `json:"metrics,omitempty"`
	Artifacts     []any    `json:"artifacts,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Errors        []string `json:"errors"`
}

// EnvelopeSucceeded reports whether a Python CLI envelope status represents
// a successful (possibly partial) command completion.
func EnvelopeSucceeded(status string) bool {
	switch status {
	case "completed", "partial", "success":
		return true
	default:
		return false
	}
}

// EnvelopeFailed reports whether the envelope status is a hard failure.
func EnvelopeFailed(status string) bool {
	switch status {
	case "failed", "error":
		return true
	default:
		return false
	}
}
