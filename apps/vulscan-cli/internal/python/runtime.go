// Package python handles Python runtime detection and validation.
package python

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// MinPythonMajor is the minimum required Python major version.
const MinPythonMajor = 3

// MinPythonMinor is the minimum required Python minor version.
const MinPythonMinor = 11

// RuntimeInfo holds information about the detected Python runtime.
type RuntimeInfo struct {
	Path    string // Full path to the Python binary
	Version string // Version string (e.g., "3.11.5")
	Major   int
	Minor   int
}

// pythonCandidates returns a list of Python binary names to search for, in order of preference.
func pythonCandidates() []string {
	return []string{"python3", "python"}
}

// venvDir returns the path to the managed venv: ~/.vulscan/venv/
func venvDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulscan", "venv")
}

// venvPython returns the path to the Python binary inside the managed venv.
func venvPython() string {
	base := venvDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(base, "Scripts", "python.exe")
	}
	return filepath.Join(base, "bin", "python")
}

// DetectRuntime finds a suitable Python 3.11+ installation.
//
// Search order:
//  1. VULSCAN_PYTHON env var (if set and valid) — set this to pin a specific
//     interpreter for debugging, CI, or container use (e.g. VULSCAN_PYTHON=python3.11).
//     The legacy name 911VULSCAN_PYTHON is still honored as a fallback.
//  2. Managed venv at ~/.vulscan/venv/ (if it exists and is valid)
//  3. python3 / python on PATH
//
// The managed-venv path (strategy 2) automatically detects the correct Python
// binary location based on the OS: "bin/python" on Unix-like systems, or
// "Scripts/python.exe" on Windows.
func DetectRuntime() (*RuntimeInfo, error) {
	// Strategy 0: honour explicit override via VULSCAN_PYTHON env var
	// (911VULSCAN_PYTHON is the legacy name, kept as a fallback).
	// If the override is set but unusable, warn and fall through rather than
	// silently using a different interpreter behind the caller's back.
	override, overrideVar := os.Getenv("VULSCAN_PYTHON"), "VULSCAN_PYTHON"
	if override == "" {
		override, overrideVar = os.Getenv("911VULSCAN_PYTHON"), "911VULSCAN_PYTHON"
	}
	if override != "" {
		info, err := checkPython(override)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: %s=%q is not a usable Python binary (%v); ignoring override\n",
				overrideVar, override, err)
		} else if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: %s=%q is Python %s, below the required %d.%d; ignoring override\n",
				overrideVar, override, info.Version, MinPythonMajor, MinPythonMinor)
		}
	}

	// Strategy 1: check managed venv
	vp := venvPython()
	if fileExists(vp) {
		if info, err := checkPython(vp); err == nil {
			if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
				return info, nil
			}
		}
	}

	// Strategy 2: check PATH
	for _, name := range pythonCandidates() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}

		info, err := checkPython(path)
		if err != nil {
			continue
		}

		if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		}
	}

	return nil, fmt.Errorf(
		"Python %d.%d+ is required but not found on PATH.\n"+
			"Install Python from https://python.org or use your system package manager.",
		MinPythonMajor, MinPythonMinor,
	)
}

// checkPython runs the given binary and extracts version info.
func checkPython(path string) (*RuntimeInfo, error) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run %s: %w", path, err)
	}

	// Output is "Python X.Y.Z\n"
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Python "))
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	return &RuntimeInfo{
		Path:    path,
		Version: version,
		Major:   major,
		Minor:   minor,
	}, nil
}

// CheckVulscanInstalled verifies that the `vulscan` package is importable.
// If the package is missing, it attempts to:
//  1. Locate libs/vulscan-core
//  2. Create a managed venv at ~/.vulscan/venv/ (if not using one already)
//  3. Install vulscan into the venv
//
// On success, it updates the RuntimeInfo to point to the venv Python.
func CheckVulscanInstalled(pythonPath string) error {
	if isVulscanImportable(pythonPath) {
		return nil
	}

	// Not installed — try to find the source and install it.
	corePath, err := findVulscanCore()
	if err != nil {
		return fmt.Errorf(
			"vulscan Python package is not installed and could not be located automatically.\n"+
				"Install it with: pip install -e <path-to-vulscan-core>\n"+
				"(%s)", err,
		)
	}

	// If we're not already using the managed venv, create one and use it.
	vp := venvPython()
	if pythonPath != vp {
		fmt.Fprintln(os.Stderr, "Creating managed Python environment at ~/.vulscan/venv/...")
		if err := createVenv(pythonPath); err != nil {
			return fmt.Errorf(
				"failed to create venv at %s: %w\n"+
					"Try manually: %s -m venv %s && %s -m pip install -e %s",
				venvDir(), err, pythonPath, venvDir(), vp, corePath,
			)
		}
		pythonPath = vp
	}

	fmt.Fprintf(os.Stderr, "Installing vulscan from %s...\n", corePath)
	if err := installVulscan(pythonPath, corePath); err != nil {
		return fmt.Errorf(
			"failed to install vulscan from %s:\n  %w\n"+
				"Try manually: %s -m pip install -e %s",
			corePath, err, pythonPath, corePath,
		)
	}

	// Verify it actually worked.
	if !isVulscanImportable(pythonPath) {
		return fmt.Errorf(
			"pip install succeeded but `import vulscan` still fails.\n"+
				"Try manually: %s -m pip install -e %s",
			pythonPath, corePath,
		)
	}

	// Save dependency hash so CheckDepsStale knows this is the baseline.
	pyprojectPath := filepath.Join(corePath, "pyproject.toml")
	if h, err := hashFile(pyprojectPath); err == nil {
		if err := writeStoredHash(h); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: could not save dependency hash at %s: %v (next run may reinstall)\n",
				depsHashPath(), err)
		}
	}

	fmt.Fprintln(os.Stderr, "vulscan installed successfully.")
	return nil
}

// EnsureRuntime is a convenience that detects a runtime, ensures vulscan
// is installed (creating a venv if necessary), and returns the final
// RuntimeInfo pointing to the correct Python binary.
func EnsureRuntime() (*RuntimeInfo, error) {
	rt, err := DetectRuntime()
	if err != nil {
		return nil, err
	}

	if err := CheckVulscanInstalled(rt.Path); err != nil {
		return nil, err
	}

	// After CheckVulscanInstalled, the venv may have been created.
	// Re-detect to pick up the venv Python if it was just created.
	vp := venvPython()
	if rt.Path != vp && fileExists(vp) && isVulscanImportable(vp) {
		if info, err := checkPython(vp); err == nil {
			rt = info
		}
	}

	// Check if dependencies have changed since last install.
	if err := CheckDepsStale(rt.Path); err != nil {
		return nil, err
	}

	return rt, nil
}

// depsHashPath returns the path to the stored dependency hash inside the venv.
func depsHashPath() string {
	return filepath.Join(venvDir(), ".deps-hash")
}

// hashFile returns the hex-encoded SHA-256 of a file's contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// readHashAt reads a stored hash from the given path, or "" if absent.
func readHashAt(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeHashAt saves a hash to the given path, creating the parent directory
// if it does not already exist.
func writeHashAt(path, hash string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(hash+"\n"), 0644)
}

// readStoredHash reads the previously stored dependency hash, or "" if absent.
func readStoredHash() string { return readHashAt(depsHashPath()) }

// writeStoredHash saves the dependency hash to the venv marker file.
func writeStoredHash(hash string) error { return writeHashAt(depsHashPath(), hash) }

// depsStalenessAt inspects pyproject.toml at corePath and the hash stored at
// hashPath, and reports whether a reinstall is needed. The boolean is true
// when deps are stale (i.e. the hash differs and a reinstall is warranted).
// The caller is expected to skip the check on any error.
func depsStalenessAt(corePath, hashPath string) (stale bool, currentHash string, err error) {
	pyprojectPath := filepath.Join(corePath, "pyproject.toml")
	currentHash, err = hashFile(pyprojectPath)
	if err != nil {
		return false, "", err
	}
	return currentHash != readHashAt(hashPath), currentHash, nil
}

// depsStaleness is the production wrapper around depsStalenessAt that uses
// the real venv hash path.
func depsStaleness(corePath string) (stale bool, currentHash string, err error) {
	return depsStalenessAt(corePath, depsHashPath())
}

// CheckDepsStale checks if pyproject.toml has changed since the last install.
// If stale, it re-runs pip install -e and updates the stored hash.
// Returns nil if deps are up-to-date or were successfully refreshed.
func CheckDepsStale(pythonPath string) error {
	return checkDepsStaleWith(pythonPath, findVulscanCore)
}

// checkDepsStaleWith is the testable core of CheckDepsStale; coreFinder is
// injected so tests can avoid os.Chdir to simulate a missing source tree.
func checkDepsStaleWith(pythonPath string, coreFinder func() (string, error)) error {
	corePath, err := coreFinder()
	if err != nil {
		// Can't find source — skip staleness check
		return nil
	}

	stale, currentHash, err := depsStaleness(corePath)
	if err != nil {
		// Can't read pyproject.toml — skip check
		return nil
	}
	if !stale {
		return nil // deps are up-to-date
	}

	fmt.Fprintln(os.Stderr, "Dependencies changed, updating vulscan installation...")
	// Known limitation: concurrent invocations that both detect stale deps
	// will race to pip-install into the same venv. pip does not support
	// concurrent writes; an OS-level lock would be needed to close this gap.
	if err := installVulscan(pythonPath, corePath); err != nil {
		return fmt.Errorf(
			"failed to update vulscan dependencies: %w\n"+
				"Try manually: %s -m pip install -e %s",
			err, pythonPath, corePath,
		)
	}

	// Store the new hash
	if err := writeStoredHash(currentHash); err != nil {
		// Non-fatal — install succeeded, just can't cache the hash
		fmt.Fprintf(os.Stderr, "Warning: could not save dependency hash: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "Dependencies updated successfully.")
	return nil
}

// createVenv creates a new venv at ~/.vulscan/venv/ using the given Python.
func createVenv(pythonPath string) error {
	dir := venvDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	cmd := exec.Command(pythonPath, "-m", "venv", dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// isVulscanImportable returns true if `python -c "import vulscan"` succeeds.
func isVulscanImportable(pythonPath string) bool {
	cmd := exec.Command(pythonPath, "-c", "from vulscan import __version__")
	return cmd.Run() == nil
}

// installVulscan runs `python -m pip install -e <corePath>`.
func installVulscan(pythonPath, corePath string) error {
	cmd := exec.Command(pythonPath, "-m", "pip", "install", "-e", corePath)
	cmd.Stdout = os.Stderr // pip output goes to stderr so it doesn't pollute JSON stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// PipUninstall returns an *exec.Cmd that runs `python -m pip uninstall vulscan -y`.
func PipUninstall(pythonPath string) *exec.Cmd {
	cmd := exec.Command(pythonPath, "-m", "pip", "uninstall", "vulscan", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd
}

// findVulscanCore locates the libs/vulscan-core directory by checking:
//  1. Relative to the running executable (walk up looking for libs/vulscan-core/pyproject.toml)
//  2. Relative to the current working directory
func findVulscanCore() (string, error) {
	marker := filepath.Join("libs", "vulscan-core", "pyproject.toml")

	// Strategy 1: walk up from the executable.
	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 { // at most 6 levels up
			candidate := filepath.Join(dir, "libs", "vulscan-core")
			if fileExists(filepath.Join(dir, marker)) {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Strategy 2: walk up from CWD.
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for range 6 {
			candidate := filepath.Join(dir, "libs", "vulscan-core")
			if fileExists(filepath.Join(dir, marker)) {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("could not find libs/vulscan-core from executable or working directory")
}

// fileExists is a small helper that returns true if path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
