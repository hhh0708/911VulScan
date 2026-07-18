package git

import (
	"fmt"
	"regexp"
	"strings"
)

// refCharset matches the characters allowed in a user-supplied git revision.
// It covers SHAs, branch/tag names, and revision syntax like HEAD~5, HEAD^,
// origin/main, and HEAD@{1}.
var refCharset = regexp.MustCompile(`^[A-Za-z0-9._/@~^{}+-]+$`)

// ValidateRef rejects user-supplied refs/commits that could be misinterpreted
// as command-line options (argument injection) or contain unexpected
// characters. Git commands here run without a shell, so the threat is a ref
// beginning with "-" being parsed as a flag (e.g. --upload-pack); we reject
// those and constrain the charset defensively. ".." is also rejected: it is
// range syntax (a..b), which makes `git rev-parse` emit multiple lines and
// is never a valid single ref (git check-ref-format forbids it too).
func ValidateRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("empty git ref")
	}
	if len(ref) > 256 {
		return fmt.Errorf("git ref too long")
	}
	if ref[0] == '-' {
		return fmt.Errorf("invalid git ref %q: must not start with '-'", ref)
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("invalid git ref %q: must not contain '..'", ref)
	}
	if !refCharset.MatchString(ref) {
		return fmt.Errorf("invalid git ref %q: contains disallowed characters", ref)
	}
	return nil
}
