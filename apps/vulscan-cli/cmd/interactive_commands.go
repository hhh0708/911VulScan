// Interactive-mode slash commands: table, parser, and default resolution.
package cmd

import (
	"fmt"
	"strings"

	"github.com/hhh0708/911vulscan-cli/internal/config"
)

// Default LLM selection used when neither env nor config pins one.
const (
	defaultProvider = "deepseek"
	defaultModel    = "deepseek-v4-pro"
)

// slashCommand describes one interactive command for help and dispatch.
type slashCommand struct {
	name string
	desc string
}

var slashCommands = []slashCommand{
	{"provider", "Select LLM provider (deepseek / anthropic / qwen / openai_compat)"},
	{"model", "Select model for the current provider"},
	{"apikey", "Set and validate the API key"},
	{"project", "Switch the active project"},
	{"scan", "Run static analysis on the active project"},
	{"dynamic", "Run Docker-isolated dynamic verification"},
	{"status", "Show current configuration"},
	{"help", "Show this command list"},
	{"exit", "Quit interactive mode"},
}

// parseSlashCommand splits an input line into (command, args, ok).
// Only lines starting with '/' are commands; the name is lower-cased.
func parseSlashCommand(input string) (string, []string, bool) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "/") {
		return "", nil, false
	}
	fields := strings.Fields(trimmed[1:])
	if len(fields) == 0 {
		return "", nil, false
	}
	return strings.ToLower(fields[0]), fields[1:], true
}

// knownSlashCommand reports whether name is a real command (exit/quit aliases
// included) so the REPL can warn on typos instead of failing silently.
func knownSlashCommand(name string) bool {
	for _, c := range slashCommands {
		if c.name == name {
			return true
		}
	}
	return name == "quit"
}

// renderHelp formats the command list for display.
func renderHelp() string {
	var b strings.Builder
	b.WriteString(styleBrand.Render("Commands") + "\n")
	width := 0
	for _, c := range slashCommands {
		if len(c.name) > width {
			width = len(c.name)
		}
	}
	for _, c := range slashCommands {
		fmt.Fprintf(&b, "  %s  %s\n",
			styleCmdName.Render("/"+c.name+strings.Repeat(" ", width-len(c.name))),
			styleCmdDesc.Render(c.desc))
	}
	b.WriteString(styleMuted.Render("\nAnything not starting with / is ignored — this console drives the\n" +
		"pipeline; it is not an LLM chat."))
	return b.String()
}

// getenvFunc matches os.Getenv for testable default resolution.
type getenvFunc func(string) string

// resolveProvider picks provider: env > config > built-in default.
func resolveProvider(getenv getenvFunc, cfg *config.Config) string {
	if v := strings.TrimSpace(getenv("VULSCAN_LLM_PROVIDER")); v != "" {
		return strings.ToLower(v)
	}
	if cfg != nil && strings.TrimSpace(cfg.Provider) != "" {
		return strings.ToLower(strings.TrimSpace(cfg.Provider))
	}
	return defaultProvider
}

// resolveModel picks model: env > config > built-in default.
func resolveModel(getenv getenvFunc, cfg *config.Config) string {
	if v := strings.TrimSpace(getenv("VULSCAN_LLM_MODEL")); v != "" {
		return v
	}
	if cfg != nil && strings.TrimSpace(cfg.DefaultModel) != "" {
		return strings.TrimSpace(cfg.DefaultModel)
	}
	return defaultModel
}

// resolveBaseURL picks base URL: env > config (openai_compat only).
func resolveBaseURL(getenv getenvFunc, cfg *config.Config) string {
	if v := strings.TrimSpace(getenv("VULSCAN_LLM_BASE_URL")); v != "" {
		return v
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.BaseURL)
	}
	return ""
}

// modelPresets lists common models per provider; "custom" allows free input.
func modelPresets(provider string) []string {
	switch provider {
	case "deepseek":
		return []string{"deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"}
	case "anthropic":
		return []string{"claude-opus-4-6", "claude-sonnet-4-6"}
	case "qwen":
		return []string{"qwen-max", "qwen-plus"}
	default:
		return nil
	}
}

// validProvider reports whether name is a selectable provider.
func validProvider(name string) bool {
	switch name {
	case "deepseek", "anthropic", "qwen", "openai_compat":
		return true
	}
	return false
}
