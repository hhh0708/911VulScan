package config

import "testing"

func TestValidateRunID(t *testing.T) {
	valid := []string{
		"20260718T103131Z_a1b2c3d4e5",
		"run-123",
		"abc_DEF",
		"0",
	}
	for _, id := range valid {
		if err := ValidateRunID(id); err != nil {
			t.Errorf("ValidateRunID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []string{
		"",        // empty
		"../../x", // path escape
		"..",      // parent segment
		"a/b",     // nested path
		"a b",     // space
		"a.b",     // dot not allowed in run IDs
	}
	for _, id := range invalid {
		if err := ValidateRunID(id); err == nil {
			t.Errorf("ValidateRunID(%q) = nil, want error", id)
		}
	}
}

func TestValidateProjectName(t *testing.T) {
	valid := []string{
		"grafana",
		"grafana/grafana", // org/repo
		"my-org/my.repo_2",
		"a.b.c",
		"A",
	}
	for _, name := range valid {
		if err := ValidateProjectName(name); err != nil {
			t.Errorf("ValidateProjectName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",          // empty
		"..",        // bare parent segment
		"../x",      // escape via first segment
		"x/..",      // escape via second segment
		"a/b/c",     // more than one slash
		"a b",       // space
		"a$b",       // illegal char
		"/abs",      // leading slash
		"trailing/", // trailing slash
		"a//b",      // empty segment
	}
	for _, name := range invalid {
		if err := ValidateProjectName(name); err == nil {
			t.Errorf("ValidateProjectName(%q) = nil, want error", name)
		}
	}
}

func TestValidateShortSHA(t *testing.T) {
	valid := []string{
		"591ceb2eec0", // short SHA
		"55cc12c59a6d7d159c1f64cd5f712a304f32d559", // full SHA
		"f", // 1 char
	}
	for _, sha := range valid {
		if err := ValidateShortSHA(sha); err != nil {
			t.Errorf("ValidateShortSHA(%q) = %v, want nil", sha, err)
		}
	}

	invalid := []string{
		"",          // empty
		"../../etc", // path escape
		"nogit",     // non-hex letters
		"55CC12c5",  // uppercase hex not allowed
		"55cc12c59a6d7d159c1f64cd5f712a304f32d559aa", // 42 chars, too long
		"HEAD~1", // rev syntax, not a SHA
	}
	for _, sha := range invalid {
		if err := ValidateShortSHA(sha); err == nil {
			t.Errorf("ValidateShortSHA(%q) = nil, want error", sha)
		}
	}
}
