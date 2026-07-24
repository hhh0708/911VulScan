package cmd

import (
	"strings"
	"testing"

	"github.com/hhh0708/911vulscan-cli/internal/config"
)

func TestShouldEnterInteractive(t *testing.T) {
	cases := []struct {
		name                string
		args                []string
		stdinTTY, stdoutTTY bool
		want                bool
	}{
		{"bare vulscan on TTY", []string{"vulscan"}, true, true, true},
		{"stdin piped", []string{"vulscan"}, false, true, false},
		{"stdout piped", []string{"vulscan"}, true, false, false},
		{"both piped", []string{"vulscan"}, false, false, false},
		{"with subcommand", []string{"vulscan", "scan"}, true, true, false},
		{"with flag", []string{"vulscan", "--json"}, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldEnterInteractive(tc.args, tc.stdinTTY, tc.stdoutTTY); got != tc.want {
				t.Fatalf("shouldEnterInteractive(%v, %v, %v) = %v, want %v",
					tc.args, tc.stdinTTY, tc.stdoutTTY, got, tc.want)
			}
		})
	}
}

func TestParseSlashCommand(t *testing.T) {
	cases := []struct {
		input    string
		wantName string
		wantArgs []string
		wantOK   bool
	}{
		{"/help", "help", nil, true},
		{"  /scan  ", "scan", nil, true},
		{"/MODEL deepseek-chat", "model", []string{"deepseek-chat"}, true},
		{"help", "", nil, false},
		{"", "", nil, false},
		{"/", "", nil, false},
		{"   ", "", nil, false},
		{"hello /help", "", nil, false},
	}
	for _, tc := range cases {
		name, args, ok := parseSlashCommand(tc.input)
		if ok != tc.wantOK {
			t.Fatalf("parseSlashCommand(%q) ok=%v, want %v", tc.input, ok, tc.wantOK)
		}
		if !tc.wantOK {
			continue
		}
		if name != tc.wantName {
			t.Fatalf("parseSlashCommand(%q) name=%q, want %q", tc.input, name, tc.wantName)
		}
		if len(args) != len(tc.wantArgs) {
			t.Fatalf("parseSlashCommand(%q) args=%v, want %v", tc.input, args, tc.wantArgs)
		}
		for i := range args {
			if args[i] != tc.wantArgs[i] {
				t.Fatalf("parseSlashCommand(%q) args=%v, want %v", tc.input, args, tc.wantArgs)
			}
		}
	}
}

func TestKnownSlashCommand(t *testing.T) {
	for _, c := range slashCommands {
		if !knownSlashCommand(c.name) {
			t.Fatalf("declared command /%s not recognized", c.name)
		}
	}
	if !knownSlashCommand("quit") {
		t.Fatal("alias /quit not recognized")
	}
	for _, bogus := range []string{"", "helper", "scanx", "providers"} {
		if knownSlashCommand(bogus) {
			t.Fatalf("bogus command /%s recognized", bogus)
		}
	}
}

func staticEnv(env map[string]string) getenvFunc {
	return func(k string) string { return env[k] }
}

func TestResolveProviderDefaults(t *testing.T) {
	if got := resolveProvider(staticEnv(nil), &config.Config{}); got != defaultProvider {
		t.Fatalf("empty env+config: got %q, want %q", got, defaultProvider)
	}
	if got := resolveProvider(staticEnv(nil), &config.Config{Provider: "Anthropic"}); got != "anthropic" {
		t.Fatalf("config provider: got %q, want anthropic", got)
	}
	env := map[string]string{"VULSCAN_LLM_PROVIDER": "qwen"}
	if got := resolveProvider(staticEnv(env), &config.Config{Provider: "deepseek"}); got != "qwen" {
		t.Fatalf("env beats config: got %q, want qwen", got)
	}
}

func TestResolveModelDefaults(t *testing.T) {
	if got := resolveModel(staticEnv(nil), &config.Config{}); got != defaultModel {
		t.Fatalf("empty env+config: got %q, want %q", got, defaultModel)
	}
	if got := resolveModel(staticEnv(nil), &config.Config{DefaultModel: "custom-x"}); got != "custom-x" {
		t.Fatalf("config model: got %q, want custom-x", got)
	}
	env := map[string]string{"VULSCAN_LLM_MODEL": "env-model"}
	if got := resolveModel(staticEnv(env), &config.Config{DefaultModel: "custom-x"}); got != "env-model" {
		t.Fatalf("env beats config: got %q, want env-model", got)
	}
}

func TestModelPresetsAndProviderValidation(t *testing.T) {
	if !validProvider("deepseek") || !validProvider("anthropic") ||
		!validProvider("qwen") || !validProvider("openai_compat") {
		t.Fatal("known provider rejected")
	}
	if validProvider("bogus") || validProvider("") {
		t.Fatal("bogus provider accepted")
	}
	if got := modelPresets("deepseek"); len(got) == 0 || got[0] != defaultModel {
		t.Fatalf("deepseek presets should start with the default model, got %v", got)
	}
	if got := modelPresets("openai_compat"); got != nil {
		t.Fatalf("openai_compat should have no presets, got %v", got)
	}
}

func TestRenderHelpCoversAllCommands(t *testing.T) {
	help := renderHelp()
	for _, c := range slashCommands {
		if !strings.Contains(help, "/"+c.name) || !strings.Contains(help, c.desc) {
			t.Fatalf("help output missing /%s", c.name)
		}
	}
}
