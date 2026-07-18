package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveAPIKey_FlagWins(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-from-env")
	got := ResolveAPIKey("sk-from-flag")
	if got != "sk-from-flag" {
		t.Fatalf("got %q, want flag value", got)
	}
}

func TestResolveAPIKey_EnvBeforeConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", dir)
	}
	cfgPath := filepath.Join(dir, "vulscan", "config.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Config{APIKey: "sk-from-file"})
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-from-env-xx")
	t.Setenv("VULSCAN_LLM_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "")
	t.Setenv("DASHSCOPE_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")

	got := ResolveAPIKey("")
	if got != "sk-from-env-xx" {
		t.Fatalf("got %q, want env value", got)
	}
}

func TestRedactSecrets(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-redact")
	out := RedactSecrets("error sk-test-redact boom")
	if out == "error sk-test-redact boom" {
		t.Fatal("expected redaction")
	}
	if contains(out, "sk-test-redact") {
		t.Fatalf("secret still present after redaction")
	}
}

func TestMaskKey(t *testing.T) {
	masked := MaskKey("sk-test-mask")
	if masked == "sk-test-mask" {
		t.Fatalf("mask unchanged: %q", masked)
	}
}

func TestMaskKeyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"", "(not set)"},                           // len 0
		{"a", "***"},                                // len 1 — must not panic
		{"ab", "***"},                               // len 2 — must not panic
		{"abcdefg", "***"},                          // len 7
		{"abcdefgh", "abc...gh"},                    // len 8
		{"abcdefghijkl", "abc...kl"},                // len 12
		{"abcdefghijklm", "abcdefg...jklm"},         // len 13
		{"sk-ant-api03-12345678", "sk-ant-...5678"}, // len 20
	} {
		if got := MaskKey(tc.key); got != tc.want {
			t.Errorf("MaskKey(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
