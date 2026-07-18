package git

import "testing"

func TestValidateRef(t *testing.T) {
	valid := []string{
		"55cc12c59a6d7d159c1f64cd5f712a304f32d559", // full SHA
		"591ceb2eec0",       // short SHA
		"main",              // branch name
		"feature/my-branch", // slashed branch
		"origin/main",       // remote-tracking ref
		"v1.2.3",            // tag
		"HEAD",              // symbolic ref
		"HEAD~5",            // tilde syntax
		"HEAD^",             // caret syntax
		"HEAD@{1}",          // reflog syntax
		"release_2024+rc1",  // plus and underscore
	}
	for _, ref := range valid {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []string{
		"",                   // empty
		"--upload-pack=evil", // option injection
		"-evil",              // leading dash
		"foo bar",            // space
		"foo;rm -rf /",       // shell metacharacters
		"$(whoami)",          // command substitution
		"foo\\bar",           // backslash
		"..",                 // dotdot range fragment w/o endpoints
	}
	for _, ref := range invalid {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("ValidateRef(%q) = nil, want error", ref)
		}
	}

	// Overlong refs are rejected.
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateRef(string(long)); err == nil {
		t.Error("ValidateRef(257 chars) = nil, want error")
	}
}
