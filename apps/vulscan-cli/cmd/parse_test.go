package cmd

import (
	"strings"
	"testing"
)

func TestParseScopeFlagDefaultIsReachable(t *testing.T) {
	flag := parseCmd.Flag("scope")
	if flag == nil {
		t.Fatal("parseCmd has no --scope flag")
	}
	if got, want := flag.DefValue, "reachable"; got != want {
		t.Errorf("--scope default = %q, want %q", got, want)
	}
}

func TestParseScopeFlagUsageMentionsChoices(t *testing.T) {
	flag := parseCmd.Flag("scope")
	if flag == nil {
		t.Fatal("parseCmd has no --scope flag")
	}
	for _, choice := range []string{"all", "reachable"} {
		if !strings.Contains(flag.Usage, choice) {
			t.Errorf("--scope usage missing %q: %q", choice, flag.Usage)
		}
	}
	for _, removed := range []string{"codeql", "exploitable", "level"} {
		if strings.Contains(flag.Usage, removed) {
			t.Errorf("--scope usage should not mention %q: %q", removed, flag.Usage)
		}
	}
}

func TestParseHasNoLevelFlag(t *testing.T) {
	if parseCmd.Flag("level") != nil {
		t.Fatal("parseCmd must not expose removed --level flag")
	}
}

func TestBuildParsePyArgsScopeForwarding(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantScope bool // true if --scope should appear in argv
	}{
		{"default reachable is omitted", "reachable", false},
		{"all is forwarded", "all", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := buildParsePyArgs("/repo", "/out", "", "auto", tc.scope, "")
			gotScope, gotValue := findFlag(args, "--scope")
			if gotScope != tc.wantScope {
				t.Errorf("--scope present = %v, want %v (argv=%v)", gotScope, tc.wantScope, args)
			}
			if tc.wantScope && gotValue != tc.scope {
				t.Errorf("--scope value = %q, want %q (argv=%v)", gotValue, tc.scope, args)
			}
			if present, _ := findFlag(args, "--level"); present {
				t.Errorf("argv must not contain --level: %v", args)
			}
		})
	}
}

func TestBuildParsePyArgsBaseline(t *testing.T) {
	args := buildParsePyArgs("/repo", "/out", "org-repo-abc1234", "python", "all", "/tmp/manifest.json")
	want := []string{
		"parse", "/repo",
		"--output", "/out",
		"--name", "org-repo-abc1234",
		"--language", "python",
		"--scope", "all",
		"--diff-manifest", "/tmp/manifest.json",
	}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

func TestScanFlagDefaults(t *testing.T) {
	scope := scanCmd.Flag("scope")
	if scope == nil || scope.DefValue != "reachable" {
		t.Fatalf("--scope default = %v, want reachable", scope)
	}
	if scanCmd.Flag("dynamic-verify") == nil {
		t.Fatal("scanCmd missing --dynamic-verify")
	}
	if scanCmd.Flag("dynamic-verify").DefValue != "false" {
		t.Fatalf("--dynamic-verify default = %q, want false", scanCmd.Flag("dynamic-verify").DefValue)
	}
	if scanCmd.Flag("no-verify") == nil {
		t.Fatal("scanCmd missing --no-verify")
	}
	if scanCmd.Flag("run-id") == nil {
		t.Fatal("scanCmd missing --run-id")
	}
	for _, removed := range []string{"level", "real-world", "llm-reachability", "skip-dynamic-test", "verify", "backoff"} {
		if scanCmd.Flag(removed) != nil {
			t.Errorf("scanCmd must not expose removed --%s flag", removed)
		}
	}
}

func TestBuildScanPyArgsForwardsCompleteRequest(t *testing.T) {
	args := buildScanPyArgs(
		"/repo", "/out", "run123", "python", "reachable", "agentic", "opus",
		false, false, false, false, false,
		0, 8,
		"", "org/repo", "https://example.com", "abc123",
		"",
	)
	required := []string{
		"--output", "/out",
		"--run-id", "run123",
		"--language", "python",
		"--scope", "reachable",
		"--enhance-mode", "agentic",
		"--model", "opus",
		"--workers", "8",
		"--repo-name", "org/repo",
		"--repo-url", "https://example.com",
		"--commit-sha", "abc123",
	}
	for i := 0; i+1 < len(required); i += 2 {
		flag, val := required[i], required[i+1]
		got, gotVal := findFlag(args, flag)
		if !got || gotVal != val {
			t.Errorf("%s = (%v, %q), want %q (argv=%v)", flag, got, gotVal, val, args)
		}
	}
	if present, _ := findFlag(args, "--backoff"); present {
		t.Errorf("scan argv must not contain --backoff: %v", args)
	}
}

// findFlag returns whether name is present in argv, and its following value
// (or "" if it has no value).
func findFlag(argv []string, name string) (bool, string) {
	for i, a := range argv {
		if a == name {
			if i+1 < len(argv) {
				return true, argv[i+1]
			}
			return true, ""
		}
	}
	return false, ""
}
