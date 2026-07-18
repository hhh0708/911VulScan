package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hhh0708/911vulscan-cli/internal/config"
	"github.com/hhh0708/911vulscan-cli/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	anthropicAPIURL = "https://api.anthropic.com/v1/messages"
)

// validationRequestURLOverride is used by tests to redirect validation requests.
var validationRequestURLOverride string

// setAPIKeyStdin reads the key from stdin instead of argv (safer for scripts).
var setAPIKeyStdin bool

type providerValidation struct {
	name       string
	url        string
	body       string
	headers    map[string]string
	authError  string
	networkErr string
}

func llmProviderValidation() providerValidation {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("VULSCAN_LLM_PROVIDER")))
	switch provider {
	case "deepseek":
		return providerValidation{
			name: "DeepSeek",
			url:  "https://api.deepseek.com/chat/completions",
			body: `{"model":"deepseek-chat","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
			headers: map[string]string{
				"authorization": "Bearer %s",
				"content-type":  "application/json",
			},
			authError:  "DeepSeek rejected the key (HTTP 401). Check your key at https://platform.deepseek.com/",
			networkErr: "could not reach DeepSeek API",
		}
	case "qwen":
		return providerValidation{
			name: "Qwen (DashScope)",
			url:  "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
			body: `{"model":"qwen-plus","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
			headers: map[string]string{
				"authorization": "Bearer %s",
				"content-type":  "application/json",
			},
			authError:  "Qwen/DashScope rejected the key (HTTP 401). Check your key at https://dashscope.console.aliyun.com/",
			networkErr: "could not reach Qwen/DashScope API",
		}
	case "openai_compat":
		baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("VULSCAN_LLM_BASE_URL")), "/")
		model := strings.TrimSpace(os.Getenv("VULSCAN_LLM_MODEL"))
		if model == "" {
			model = "gpt-4o"
		}
		if baseURL == "" {
			return providerValidation{
				name:      "OpenAI-compatible",
				authError: "VULSCAN_LLM_BASE_URL is required when VULSCAN_LLM_PROVIDER=openai_compat",
			}
		}
		return providerValidation{
			name: "OpenAI-compatible",
			url:  baseURL + "/chat/completions",
			body: fmt.Sprintf(`{"model":%q,"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model),
			headers: map[string]string{
				"authorization": "Bearer %s",
				"content-type":  "application/json",
			},
			authError:  "OpenAI-compatible endpoint rejected the key (HTTP 401)",
			networkErr: "could not reach OpenAI-compatible endpoint",
		}
	default:
		return providerValidation{
			name: "Anthropic",
			url:  anthropicAPIURL,
			body: `{"model":"claude-haiku-4-5-20251001","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
			headers: map[string]string{
				"x-api-key":         "%s",
				"anthropic-version": "2023-06-01",
				"content-type":      "application/json",
			},
			authError:  "Anthropic rejected the key (HTTP 401). Double-check it at https://console.anthropic.com/settings/keys",
			networkErr: "could not reach Anthropic API",
		}
	}
}

func validateAPIKey(key string) error {
	cfg := llmProviderValidation()
	if cfg.url == "" {
		return fmt.Errorf("%s", cfg.authError)
	}

	url := cfg.url
	if validationRequestURLOverride != "" {
		url = validationRequestURLOverride
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(cfg.body))
	if err != nil {
		return fmt.Errorf("failed to build validation request: %w", err)
	}
	for header, value := range cfg.headers {
		if strings.Contains(value, "%s") {
			req.Header.Set(header, fmt.Sprintf(value, key))
		} else {
			req.Header.Set(header, value)
		}
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Never leak credentials to a different host via redirect.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("x-api-key")
				req.Header.Del("authorization")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", cfg.networkErr, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s", cfg.authError)
	}
	// Only 2xx proves the endpoint accepted the key; anything else (400,
	// 403, 5xx, a proxy intercept page, ...) is a validation failure.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s validation failed: unexpected HTTP status %d", cfg.name, resp.StatusCode)
	}
	return nil
}

func errPositionalAPIKey() error {
	return fmt.Errorf(
		"positional API key arguments are not allowed; " +
			"use an interactive prompt (`vulscan set-api-key`) or `--stdin`",
	)
}

func readAPIKeyInput() (string, error) {
	if setAPIKeyStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return strings.TrimSpace(scanner.Text()), nil
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no API key provided on stdin")
	}
	// Interactive silent prompt (does not echo; avoids shell history).
	fmt.Fprint(os.Stderr, "Enter API key (input hidden): ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key",
	Short: "Save your LLM API key",
	Long: `Save your LLM API key to the 911VulScan config file.

The key is stored in ~/.config/vulscan/config.json with restricted
permissions (0600). This is required before running enhance, analyze,
verify, or scan.

Positional key arguments are rejected. Provide the key only via a
hidden interactive prompt or --stdin so it never appears in argv or
shell history.

By default the key is validated against Anthropic. For DeepSeek, Qwen,
or other OpenAI-compatible providers, set VULSCAN_LLM_PROVIDER before
running this command.

Examples:
  vulscan set-api-key
  echo "$ANTHROPIC_API_KEY" | vulscan set-api-key --stdin
  VULSCAN_LLM_PROVIDER=deepseek vulscan set-api-key --stdin`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errPositionalAPIKey()
		}
		return nil
	},
	Run: runSetAPIKey,
}

func init() {
	setAPIKeyCmd.Flags().BoolVar(&setAPIKeyStdin, "stdin", false, "Read API key from stdin (recommended for scripts)")
}

func runSetAPIKey(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		output.PrintError(errPositionalAPIKey().Error())
		os.Exit(1)
	}
	key, err := readAPIKeyInput()
	if err != nil {
		output.PrintError(config.RedactSecrets(err.Error()))
		os.Exit(1)
	}
	if key == "" {
		output.PrintError("API key cannot be empty")
		os.Exit(1)
	}

	provider := llmProviderValidation()
	fmt.Fprintf(os.Stderr, "Validating API key with %s... ", provider.name)
	if err := validateAPIKey(key); err != nil {
		fmt.Fprintf(os.Stderr, "\n")
		output.PrintError(config.RedactSecrets(err.Error(), key))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "OK\n")

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(config.RedactSecrets(err.Error(), key))
		os.Exit(1)
	}

	cfg.APIKey = key

	if err := config.Save(cfg); err != nil {
		output.PrintError(config.RedactSecrets(err.Error(), key))
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n")
	output.PrintSuccess(fmt.Sprintf("API key saved (%s)", config.MaskKey(key)))
	fmt.Fprintf(os.Stderr, "\n")
}
