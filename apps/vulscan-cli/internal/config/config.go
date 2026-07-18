// Package config handles persistent configuration for the 911VulScan CLI.
//
// Configuration is stored in ~/.config/vulscan/config.json (or
// $XDG_CONFIG_HOME/vulscan/config.json on Linux). The file is created
// with 0600 permissions since it may contain API keys.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config holds the persistent CLI configuration.
type Config struct {
	APIKey        string `json:"api_key,omitempty"`
	DefaultModel  string `json:"default_model,omitempty"`
	ActiveProject string `json:"active_project,omitempty"`
}

// configDir returns the base directory for vulscan config files.
// On macOS/Linux: $XDG_CONFIG_HOME/vulscan or ~/.config/vulscan
// On Windows: %APPDATA%\vulscan
func configDir() (string, error) {
	// Use Go's built-in UserConfigDir which handles platform differences:
	//   macOS:   ~/Library/Application Support
	//   Linux:   $XDG_CONFIG_HOME or ~/.config
	//   Windows: %APPDATA%
	//
	// However, on macOS we prefer ~/.config for CLI tools (standard for
	// developer tools like gh, docker, aws). UserConfigDir returns
	// ~/Library/Application Support which is more for GUI apps.
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "vulscan"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, ".config", "vulscan"), nil
	}

	// Windows: use %APPDATA%
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(dir, "vulscan"), nil
}

// Path returns the full path to the config file.
func Path() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config file. Returns an empty Config if the file
// does not exist (not an error — first run).
//
// On Unix, the file must be mode 0600 (no group/other access) when it
// contains credentials. Insecure permissions are refused.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to stat config: %w", err)
	}

	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return nil, fmt.Errorf(
				"refusing to read credentials from %s: permissions %#o must be 0600",
				path, mode,
			)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}

	return &cfg, nil
}

// Save writes the config to disk with restricted permissions.
// The write is atomic (temp file + rename, same style as SaveScanMeta)
// so a crash never leaves a truncated credentials file behind.
func Save(cfg *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	data = append(data, '\n')

	// An existing file may carry loose permissions from an older version;
	// tighten them first so credentials are never left world-readable.
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("failed to secure existing config: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, "config.json.tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to secure temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// credentialEnvVars is the ordered list of environment variables checked
// when resolving an API key (after an explicit flag value).
var credentialEnvVars = []string{
	"VULSCAN_LLM_API_KEY",
	"ANTHROPIC_API_KEY",
	"DEEPSEEK_API_KEY",
	"DASHSCOPE_API_KEY",
	"OPENAI_API_KEY",
}

// ResolveAPIKey returns the API key using the precedence:
//
//	flag > environment variables > 0600 user config file
//
// Returns empty string if no key is found. Never logs the raw value.
func ResolveAPIKey(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue)
	}

	for _, name := range credentialEnvVars {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}

	cfg, err := Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.APIKey)
}

// RedactSecrets replaces known secret substrings in text for safe logging.
func RedactSecrets(text string, extras ...string) string {
	out := text
	secrets := append([]string{}, extras...)
	for _, name := range credentialEnvVars {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			secrets = append(secrets, v)
		}
	}
	if cfg, err := Load(); err == nil && cfg.APIKey != "" {
		secrets = append(secrets, cfg.APIKey)
	}
	for _, s := range secrets {
		if len(s) >= 6 {
			out = strings.ReplaceAll(out, s, "***REDACTED***")
		}
	}
	return out
}

// DataDir returns the root data directory: ~/.vulscan/
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".vulscan"), nil
}

// ProjectsDir returns ~/.vulscan/projects/
func ProjectsDir() (string, error) {
	dataDir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "projects"), nil
}

// ProjectDir returns the directory for a specific project.
// Name is "org/repo", so the path is ~/.vulscan/projects/org/repo/
//
// Callers pass user input here; ValidateProjectName is the front-line
// check, joinUnder the Clean+prefix backstop so a bad name can never
// escape the projects root.
func ProjectDir(name string) (string, error) {
	projDir, err := ProjectsDir()
	if err != nil {
		return "", err
	}
	return joinUnder(projDir, name)
}

// ScanDir returns the scan directory for a specific project, commit SHA, and language.
// ~/.vulscan/projects/org/repo/scans/{shortSHA}/{language}/
func ScanDir(projectName, shortSHA, language string) (string, error) {
	projDir, err := ProjectDir(projectName)
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, "scans", shortSHA, language), nil
}

// MaskKey returns a masked version of an API key for display.
// Shows the first 7 and last 4 characters; keys too short to mask
// safely are fully hidden.
func MaskKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) < 8 {
		return "***"
	}
	if len(key) <= 12 {
		return key[:3] + "..." + key[len(key)-2:]
	}
	return key[:7] + "..." + key[len(key)-4:]
}
