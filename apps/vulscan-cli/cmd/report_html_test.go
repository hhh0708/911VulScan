package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveFinalScanArtifactPathRequiresPipelineOutput(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.json")
	if err := os.WriteFile(results, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveFinalScanArtifactPath(results)
	if err == nil {
		t.Fatal("expected error when pipeline_output.json missing")
	}
	if !strings.Contains(err.Error(), "FinalScanArtifact") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveFinalScanArtifactPathUsesSiblingPipelineOutput(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.json")
	pipeline := filepath.Join(dir, "pipeline_output.json")
	if err := os.WriteFile(results, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pipeline, []byte(`{"schema_version":"1.0","findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveFinalScanArtifactPath(results)
	if err != nil {
		t.Fatal(err)
	}
	if got != pipeline {
		t.Fatalf("got %q want %q", got, pipeline)
	}
}

func TestRunHTMLReportSourceDoesNotReadLegacyVerdict(t *testing.T) {
	// Static guard: HTML path must not load CONFIRMED/NOT_REPRODUCED from results.json.
	src, err := os.ReadFile("report.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, banned := range []string{
		`"CONFIRMED"`,
		`"NOT_REPRODUCED"`,
		"findings_verified",
		"attack_vector",
		"llm_context",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("report.go must not reference legacy %s", banned)
		}
	}
	if !strings.Contains(text, "report-data") {
		t.Fatal("runHTMLReport must call report-data")
	}
	if !strings.Contains(text, "resolveFinalScanArtifactPath") {
		t.Fatal("runHTMLReport must resolve FinalScanArtifact")
	}
	if !strings.Contains(text, "FinalScanArtifact integrity error") {
		t.Fatal("runHTMLReport must propagate integrity failures")
	}
	if strings.Contains(text, "generate_report.py") || strings.Contains(text, "export_csv.py") {
		t.Fatal("runHTMLReport must not fall back to legacy Python HTML/CSV scripts")
	}
}
