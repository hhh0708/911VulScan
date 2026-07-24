// Interactive mode: bare `vulscan` in a TTY launches a Claude Code-style
// console with a loading animation and slash commands driving the pipeline.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/hhh0708/911vulscan-cli/internal/config"
)

// shouldEnterInteractive gates the interactive console: only a bare
// `vulscan` invocation with both streams on a terminal qualifies.
func shouldEnterInteractive(args []string, stdinTTY, stdoutTTY bool) bool {
	return len(args) == 1 && stdinTTY && stdoutTTY
}

// runInteractive is the interactive console entry point.
func runInteractive() error {
	spin := newSpinner("Initializing 911VulScan…")
	spin.start()

	cfg, err := config.Load()
	spin.done()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Effective LLM selection (env > config > defaults) is exported so
	// child commands and key validation see the same values.
	applyLLMEnv(cfg)

	// Graceful Ctrl+C: say goodbye instead of dying silently.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer signal.Stop(sigChan)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n\n  "+styleMuted.Render("Bye."))
		os.Exit(0)
	}()

	printBanner(version, currentProvider(cfg), currentModel(cfg), maskedConfiguredKey(), activeProjectName(cfg))

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, stylePrompt.Render("vulscan")+styleMuted.Render(" > "))
		line, err := reader.ReadString('\n')
		if err != nil { // Ctrl+D / EOF
			fmt.Fprintln(os.Stderr, "\n  "+styleMuted.Render("Bye."))
			return nil
		}
		name, args, ok := parseSlashCommand(line)
		if !ok {
			if strings.TrimSpace(line) != "" {
				uiHint("Type /help to see available commands.")
			}
			continue
		}
		if !knownSlashCommand(name) {
			uiFail("Unknown command /%s — try /help", name)
			continue
		}
		quit := dispatchSlashCommand(name, args, cfg)
		if quit {
			fmt.Fprintln(os.Stderr, "  "+styleMuted.Render("Bye."))
			return nil
		}
	}
}

// dispatchSlashCommand runs one command. Returns true when the REPL should exit.
func dispatchSlashCommand(name string, args []string, cfg *config.Config) bool {
	switch name {
	case "help":
		fmt.Fprintln(os.Stderr, renderHelp())
	case "status":
		printBanner(version, currentProvider(cfg), currentModel(cfg), maskedConfiguredKey(), activeProjectName(cfg))
	case "provider":
		interactivePickProvider(cfg)
	case "model":
		interactivePickModel(cfg)
	case "apikey":
		interactiveSetAPIKey(cfg)
	case "project":
		interactivePickProject(cfg)
	case "scan":
		interactiveRunPipeline(cfg, "scan")
	case "dynamic":
		interactiveRunPipeline(cfg, "dynamic-test")
	case "exit", "quit":
		return true
	}
	return false
}

// currentProvider/currentModel re-resolve so /status reflects env changes.
func currentProvider(cfg *config.Config) string { return resolveProvider(os.Getenv, cfg) }
func currentModel(cfg *config.Config) string    { return resolveModel(os.Getenv, cfg) }

// maskedConfiguredKey shows the effective key without exposing it.
func maskedConfiguredKey() string {
	return config.MaskKey(config.ResolveAPIKey(""))
}

// activeProjectName renders the active project for the status panel.
func activeProjectName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.ActiveProject
}

// applyLLMEnv exports the effective provider/model/base URL into the
// process environment so the Python core and key validation pick them up.
func applyLLMEnv(cfg *config.Config) {
	_ = os.Setenv("VULSCAN_LLM_PROVIDER", resolveProvider(os.Getenv, cfg))
	_ = os.Setenv("VULSCAN_LLM_MODEL", resolveModel(os.Getenv, cfg))
	if base := resolveBaseURL(os.Getenv, cfg); base != "" {
		_ = os.Setenv("VULSCAN_LLM_BASE_URL", base)
	}
}

// saveConfig reloads the on-disk config, applies mutate, and saves. The
// caller's in-memory cfg is refreshed from disk first so concurrent edits
// (e.g. `vulscan set-api-key` in another terminal) are not clobbered.
func saveConfig(cfg *config.Config, mutate func(*config.Config)) error {
	fresh, err := config.Load()
	if err != nil {
		return err
	}
	mutate(fresh)
	if err := config.Save(fresh); err != nil {
		return err
	}
	*cfg = *fresh
	return nil
}

// interactivePickProvider runs the /provider select flow.
func interactivePickProvider(cfg *config.Config) {
	choice := currentProvider(cfg)
	sel := huh.NewSelect[string]().
		Title("Select LLM provider").
		Options(
			huh.NewOption("DeepSeek", "deepseek"),
			huh.NewOption("Anthropic", "anthropic"),
			huh.NewOption("Qwen (DashScope)", "qwen"),
			huh.NewOption("OpenAI-compatible", "openai_compat"),
		).
		Value(&choice)
	if err := sel.Run(); err != nil {
		uiHint("Cancelled.")
		return
	}
	if !validProvider(choice) {
		uiFail("Unsupported provider %q", choice)
		return
	}

	baseURL := resolveBaseURL(os.Getenv, cfg)
	if choice == "openai_compat" {
		input := huh.NewInput().
			Title("Base URL for the OpenAI-compatible endpoint").
			Placeholder("https://your-endpoint/v1").
			Value(&baseURL)
		if err := input.Run(); err != nil {
			uiHint("Cancelled.")
			return
		}
		baseURL = strings.TrimSpace(baseURL)
		if baseURL == "" {
			uiFail("Base URL is required for openai_compat")
			return
		}
	}

	if err := saveConfig(cfg, func(c *config.Config) {
		c.Provider = choice
		if choice == "openai_compat" {
			c.BaseURL = baseURL
		}
	}); err != nil {
		uiFail("Failed to save config: %s", config.RedactSecrets(err.Error()))
		return
	}
	applyLLMEnv(cfg)
	uiOK("Provider set to %s", choice)
}

// interactivePickModel runs the /model select flow.
func interactivePickModel(cfg *config.Config) {
	provider := currentProvider(cfg)
	presets := modelPresets(provider)

	const customSentinel = "__custom__"
	choice := customSentinel
	if len(presets) > 0 {
		choice = currentModel(cfg)
		opts := make([]huh.Option[string], 0, len(presets)+1)
		for _, m := range presets {
			label := m
			if m == defaultModel && provider == defaultProvider {
				label += "  (default)"
			}
			opts = append(opts, huh.NewOption(label, m))
		}
		opts = append(opts, huh.NewOption("Custom…", customSentinel))
		sel := huh.NewSelect[string]().
			Title(fmt.Sprintf("Select model (%s)", provider)).
			Options(opts...).
			Value(&choice)
		if err := sel.Run(); err != nil {
			uiHint("Cancelled.")
			return
		}
	}

	if choice == customSentinel {
		choice = currentModel(cfg)
		input := huh.NewInput().
			Title("Model id").
			Placeholder(defaultModel).
			Value(&choice)
		if err := input.Run(); err != nil {
			uiHint("Cancelled.")
			return
		}
	}
	choice = strings.TrimSpace(choice)
	if choice == "" {
		uiFail("Model cannot be empty")
		return
	}

	if err := saveConfig(cfg, func(c *config.Config) { c.DefaultModel = choice }); err != nil {
		uiFail("Failed to save config: %s", config.RedactSecrets(err.Error()))
		return
	}
	applyLLMEnv(cfg)
	uiOK("Model set to %s", choice)
}

// interactiveSetAPIKey runs the /apikey flow: silent prompt, live
// validation against the current provider, then save with 0600 perms.
func interactiveSetAPIKey(cfg *config.Config) {
	key, err := readAPIKeyInput()
	if err != nil {
		uiFail("%s", config.RedactSecrets(err.Error()))
		return
	}
	if key == "" {
		uiFail("API key cannot be empty")
		return
	}

	provider := llmProviderValidation()
	spin := newSpinner(fmt.Sprintf("Validating with %s…", provider.name))
	spin.start()
	err = validateAPIKey(key)
	spin.done()
	if err != nil {
		uiFail("%s", config.RedactSecrets(err.Error(), key))
		return
	}

	if err := saveConfig(cfg, func(c *config.Config) { c.APIKey = key }); err != nil {
		uiFail("Failed to save config: %s", config.RedactSecrets(err.Error(), key))
		return
	}
	uiOK("API key saved (%s)", config.MaskKey(key))
}

// interactivePickProject runs the /project select flow.
func interactivePickProject(cfg *config.Config) {
	names, err := config.ListProjects()
	if err != nil {
		uiFail("Failed to list projects: %s", err)
		return
	}
	if len(names) == 0 {
		uiHint("No projects yet. Initialize one first:  vulscan init <repo-url-or-path> -l <language>")
		return
	}

	choice := cfg.ActiveProject
	opts := make([]huh.Option[string], 0, len(names))
	for _, n := range names {
		opts = append(opts, huh.NewOption(n, n))
	}
	sel := huh.NewSelect[string]().
		Title("Switch active project").
		Options(opts...).
		Value(&choice)
	if err := sel.Run(); err != nil {
		uiHint("Cancelled.")
		return
	}

	if err := config.SetActiveProject(choice); err != nil {
		uiFail("Failed to switch project: %s", err)
		return
	}
	cfg.ActiveProject = choice
	uiOK("Active project: %s", choice)
}

// interactiveRunPipeline executes an existing CLI command (scan /
// dynamic-test) as a child process with stdio attached, so checkpoint
// prompts, progress output, and summaries behave exactly like the
// non-interactive CLI. Env (incl. provider/model) is inherited.
func interactiveRunPipeline(cfg *config.Config, subcommand string) {
	if _, err := config.ActiveProject(); err != nil {
		uiHint("No active project — pick one with /project (or run: vulscan init <path> -l <language>)")
		return
	}
	if config.ResolveAPIKey("") == "" {
		uiHint("No API key configured — set one with /apikey")
		return
	}

	exe, err := os.Executable()
	if err != nil {
		uiFail("Cannot locate the vulscan binary: %s", err)
		return
	}
	uiInfo("Running: vulscan %s", subcommand)
	fmt.Fprintln(os.Stderr)

	child := exec.Command(exe, subcommand)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()
	runErr := child.Run()

	fmt.Fprintln(os.Stderr)
	switch {
	case runErr == nil:
		uiOK("vulscan %s finished", subcommand)
	default:
		exitCode := 1
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
		if exitCode == 130 {
			uiHint("vulscan %s interrupted — checkpoints allow resuming later", subcommand)
		} else {
			uiFail("vulscan %s failed (exit %d)", subcommand, exitCode)
		}
	}
}
