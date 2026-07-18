package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Whitelists for user-supplied values that end up in filesystem paths.
// Anything matching these cannot escape its intended parent directory.
var (
	// runIDPattern allows timestamp-and-hex style run IDs (and plain slugs).
	runIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// projectNamePattern allows "repo" or "org/repo" style names.
	projectNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)?$`)
	// shortSHAPattern allows hex SHAs (short or full, 1-40 chars).
	shortSHAPattern = regexp.MustCompile(`^[a-f0-9]{1,40}$`)
)

// ValidateRunID rejects a --run-id value that could escape
// {output}/runs/ when joined into a path (e.g. "../../x").
func ValidateRunID(runID string) error {
	if !runIDPattern.MatchString(runID) {
		return fmt.Errorf(
			"invalid --run-id %q: only letters, digits, '_' and '-' are allowed", runID)
	}
	return nil
}

// ValidateProjectName rejects a project name that is not "name" or
// "org/name" made of safe characters, or that contains a ".." segment
// (which would escape ~/.vulscan/projects/ when joined into a path).
func ValidateProjectName(name string) error {
	if !projectNamePattern.MatchString(name) {
		return fmt.Errorf(
			"invalid project name %q: expected <name> or <org>/<name> "+
				"using only letters, digits, '.', '_' and '-'", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return fmt.Errorf("invalid project name %q: must not contain '..'", name)
		}
	}
	return nil
}

// ValidateShortSHA is a defense-in-depth check for the commit SHA fragment
// used in scan directory paths: hex only, so it can never escape its parent.
func ValidateShortSHA(sha string) error {
	if !shortSHAPattern.MatchString(sha) {
		return fmt.Errorf("invalid commit SHA %q: expected 1-40 hex characters", sha)
	}
	return nil
}

// joinUnder joins elem onto root and verifies the result stays inside root.
// Callers are expected to have validated elem already; this is the
// filepath.Clean-based backstop for every path join rooted at a fixed dir.
func joinUnder(root, elem string) (string, error) {
	joined := filepath.Clean(filepath.Join(root, elem))
	if joined != root && !strings.HasPrefix(joined, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes base directory %s", elem, root)
	}
	return joined, nil
}
