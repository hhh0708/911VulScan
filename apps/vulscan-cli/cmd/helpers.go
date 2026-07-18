package cmd

import (
	"github.com/hhh0708/911vulscan-cli/internal/python"
	"github.com/hhh0708/911vulscan-cli/internal/types"
)

// ensurePython detects the Python runtime and validates that vulscan is installed.
// If needed, creates a managed venv at ~/.vulscan/venv/ and installs the package.
func ensurePython() (*python.RuntimeInfo, error) {
	return python.EnsureRuntime()
}

// exitCodeForResult maps a Python invocation result to the CLI process exit
// code. Python can exit 0 while reporting a failed envelope status; map that
// to 1 so CI never treats a failed run as a success.
func exitCodeForResult(result *python.InvokeResult) int {
	if result.ExitCode == 0 && !types.EnvelopeSucceeded(result.Envelope.Status) {
		return 1
	}
	return result.ExitCode
}
