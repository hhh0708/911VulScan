package types

import "testing"

func TestEnvelopeSucceeded(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"completed", true},
		{"partial", true},
		{"success", true},
		{"failed", false},
		{"error", false},
		{"interrupted", false},
		{"", false},
	} {
		if got := EnvelopeSucceeded(tc.status); got != tc.want {
			t.Errorf("EnvelopeSucceeded(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestEnvelopeFailed(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"failed", true},
		{"error", true},
		{"completed", false},
		{"partial", false},
		{"interrupted", false},
	} {
		if got := EnvelopeFailed(tc.status); got != tc.want {
			t.Errorf("EnvelopeFailed(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}
