package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateAPIKey_Rejects401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	orig := validationRequestURLOverride
	defer func() { validationRequestURLOverride = orig }()
	validationRequestURLOverride = server.URL

	err := validateAPIKey("sk-bad-key")
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if got := err.Error(); !contains(got, "401") {
		t.Errorf("error should mention 401, got: %s", got)
	}
}

func TestValidateAPIKey_AcceptsValid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"h"}],"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	orig := validationRequestURLOverride
	defer func() { validationRequestURLOverride = orig }()
	validationRequestURLOverride = server.URL

	if err := validateAPIKey("sk-good-key"); err != nil {
		t.Fatalf("expected nil error for 200 response, got: %v", err)
	}
}

func TestValidateAPIKey_SendsCorrectHeaders(t *testing.T) {
	var gotKey, gotVersion, gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotContentType = r.Header.Get("content-type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	orig := validationRequestURLOverride
	defer func() { validationRequestURLOverride = orig }()
	validationRequestURLOverride = server.URL

	_ = validateAPIKey("sk-test-123")

	if gotKey != "sk-test-123" {
		t.Errorf("x-api-key = %q, want %q", gotKey, "sk-test-123")
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want %q", gotVersion, "2023-06-01")
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q, want %q", gotContentType, "application/json")
	}
}

func TestValidateAPIKey_DeepSeekUsesBearerAuth(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer server.Close()

	origURL := validationRequestURLOverride
	defer func() { validationRequestURLOverride = origURL }()
	validationRequestURLOverride = server.URL

	origProvider := os.Getenv("VULSCAN_LLM_PROVIDER")
	defer os.Setenv("VULSCAN_LLM_PROVIDER", origProvider)
	os.Setenv("VULSCAN_LLM_PROVIDER", "deepseek")

	if err := validateAPIKey("sk-deepseek"); err != nil {
		t.Fatalf("expected nil error for deepseek validation, got: %v", err)
	}
	if gotAuth != "Bearer sk-deepseek" {
		t.Errorf("authorization = %q, want %q", gotAuth, "Bearer sk-deepseek")
	}
}

func TestSetAPIKey_RejectsPositionalArgs(t *testing.T) {
	cmd := &cobra.Command{Use: "set-api-key"}
	cmd.Args = setAPIKeyCmd.Args
	err := cmd.Args(cmd, []string{"sk-test-123"})
	if err == nil {
		t.Fatal("expected error for positional API key argument")
	}
	msg := err.Error()
	if !contains(msg, "positional") {
		t.Fatalf("error should mention positional args, got: %s", msg)
	}
	if contains(msg, "sk-test-123") {
		t.Fatalf("error must not echo the provided key material")
	}
}

func TestSetAPIKey_AllowsNoArgs(t *testing.T) {
	cmd := &cobra.Command{Use: "set-api-key"}
	cmd.Args = setAPIKeyCmd.Args
	if err := cmd.Args(cmd, nil); err != nil {
		t.Fatalf("expected nil for no args, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
