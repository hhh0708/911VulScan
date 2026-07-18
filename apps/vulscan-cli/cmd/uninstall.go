package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hhh0708/911vulscan-cli/internal/config"
	"github.com/hhh0708/911vulscan-cli/internal/python"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove vulscan from this system",
	Long: `Remove the vulscan Python package and managed venv.

By default, only the Python environment is removed:
  - The managed venv at ~/.vulscan/venv/
  - The vulscan pip package

Configuration and scan data are preserved:
  - ~/.config/vulscan/  (API key, active project)
  - ~/.vulscan/projects/ (scan results, datasets)

Use --hard to also remove all configuration and data.`,
	Run: runUninstall,
}

var uninstallHard bool

func init() {
	uninstallCmd.Flags().BoolVar(&uninstallHard, "hard", false, "Also remove config (~/.config/vulscan/) and data (~/.vulscan/)")
}

func runUninstall(cmd *cobra.Command, args []string) {
	mode := "soft"
	if uninstallHard {
		mode = "hard"
	}

	// Resolve paths
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(2)
	}

	venvDir := filepath.Join(home, ".vulscan", "venv")
	dataDir := filepath.Join(home, ".vulscan")

	configDir, err := config.Path()
	if err != nil {
		configDir = filepath.Join(home, ".config", "vulscan", "config.json")
	}
	configDirPath := filepath.Dir(configDir)

	// Resolve binary path
	exePath, _ := os.Executable()
	if exePath != "" {
		exePath, _ = filepath.EvalSymlinks(exePath)
	}

	// Show what will be removed
	fmt.Fprintln(os.Stderr, "This will remove:")
	if exePath != "" {
		fmt.Fprintf(os.Stderr, "  - vulscan binary at %s\n", exePath)
	}
	fmt.Fprintf(os.Stderr, "  - Managed Python venv at %s\n", venvDir)
	fmt.Fprintln(os.Stderr, "  - vulscan pip package")

	if mode == "hard" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  AND (--hard):")
		fmt.Fprintf(os.Stderr, "  - Configuration at %s\n", configDirPath)
		fmt.Fprintf(os.Stderr, "  - All project data at %s\n", dataDir)
	} else {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Preserved:")
		fmt.Fprintf(os.Stderr, "  - Configuration at %s\n", configDirPath)
		fmt.Fprintf(os.Stderr, "  - Project data at %s\n", dataDir)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Continue? [y/N] ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		fmt.Fprintln(os.Stderr, "Aborted.")
		return
	}

	fmt.Fprintln(os.Stderr, "")

	// 1. Uninstall pip package from the venv (or system)
	rt, _ := python.DetectRuntime()
	if rt != nil {
		fmt.Fprintln(os.Stderr, "Uninstalling vulscan pip package...")
		uninstallCmd := python.PipUninstall(rt.Path)
		if err := uninstallCmd.Run(); err != nil {
			// Non-fatal — the package might not be installed via pip
			fmt.Fprintf(os.Stderr, "  pip uninstall skipped (package may not be pip-installed): %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "  Done.")
		}
	}

	// 2. Remove managed venv
	if dirExists(venvDir) {
		fmt.Fprintf(os.Stderr, "Removing venv at %s...\n", venvDir)
		if err := os.RemoveAll(venvDir); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: failed to remove venv: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "  Done.")
		}
	}

	// 3. Hard mode: remove config and data
	if mode == "hard" {
		if dirExists(configDirPath) {
			fmt.Fprintf(os.Stderr, "Removing config at %s...\n", configDirPath)
			if err := os.RemoveAll(configDirPath); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to remove config: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "  Done.")
			}
		}

		if dirExists(dataDir) {
			fmt.Fprintf(os.Stderr, "Removing data at %s...\n", dataDir)
			if err := os.RemoveAll(dataDir); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to remove data: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "  Done.")
			}
		}
	}

	// Remove the binary itself (do this last since we're the running process)
	if exePath != "" {
		fmt.Fprintf(os.Stderr, "Removing binary at %s...\n", exePath)
		if err := os.Remove(exePath); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not remove binary: %v\n", err)
			fmt.Fprintf(os.Stderr, "  Remove manually: rm %s\n", exePath)
		} else {
			fmt.Fprintln(os.Stderr, "  Done.")
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Uninstall complete.")

	if mode != "hard" {
		fmt.Fprintln(os.Stderr, "To also remove config and data, reinstall and run: vulscan uninstall --hard")
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
