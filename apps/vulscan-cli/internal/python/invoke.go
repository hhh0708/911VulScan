// Package python provides subprocess invocation of the Python CLI.
package python

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hhh0708/911vulscan-cli/internal/types"
)

// maxStdoutBytes caps how much of the child's stdout is retained in memory.
// The JSON envelope is emitted last, so on overflow the tail is kept.
const maxStdoutBytes = 8 << 20 // 8 MiB

// InvokeResult holds the result of a Python CLI invocation.
type InvokeResult struct {
	Envelope types.Envelope
	ExitCode int
}

// Invoke runs `python -m vulscan <args>` and returns the parsed JSON result.
//
// - stderr is streamed to the terminal in real-time (progress messages)
// - stdout is captured and parsed as JSON
// - Working directory is set to the vulscan-core lib directory if provided
// - If apiKey is non-empty, it is injected as ANTHROPIC_API_KEY in the subprocess
func Invoke(pythonPath string, args []string, workDir string, quiet bool, apiKey string) (*InvokeResult, error) {
	cmdArgs := append([]string{"-m", "vulscan"}, args...)
	cmd := exec.Command(pythonPath, cmdArgs...)

	if workDir != "" {
		cmd.Dir = workDir
	}

	// Pass through environment (Python needs ANTHROPIC_API_KEY, etc.)
	// If an API key is provided via flag or config, inject it into the
	// subprocess environment so Python picks it up regardless of .env files.
	cmd.Env = os.Environ()
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}

	// Capture stdout (JSON output)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Stream stderr to terminal (progress messages)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Python process: %w", err)
	}

	// Forward SIGINT/SIGTERM to the Python subprocess so Ctrl+C kills it.
	sigChan := make(chan os.Signal, 1)
	var interrupted atomic.Bool
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		// Keep forwarding until the channel closes: a second Ctrl+C must
		// also reach the child, not be swallowed by an exited goroutine.
		for sig := range sigChan {
			interrupted.Store(true)
			// Forward signal to Python subprocess
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
			// Give Python a few seconds to exit gracefully, then force kill
			time.AfterFunc(5*time.Second, func() {
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
			})
		}
	}()
	defer func() {
		signal.Stop(sigChan)
		close(sigChan)
	}()

	// Stream stderr in a goroutine
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		streamStderr(stderr, quiet)
	}()

	// Read stdout, capped at maxStdoutBytes (tail kept on overflow).
	var stdoutBuf tailBuffer
	stdoutBuf.max = maxStdoutBytes
	if _, err := io.Copy(&stdoutBuf, stdout); err != nil {
		// Kill and reap the child so a read failure never leaks the process.
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-stderrDone
		_ = cmd.Wait()
		return nil, fmt.Errorf("failed to read stdout: %w", err)
	}

	// Wait for stderr streaming to finish
	<-stderrDone

	// Wait for process to exit
	exitErr := cmd.Wait()
	exitCode := 0
	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("failed waiting for Python process: %w", exitErr)
		}
	}

	// Parse JSON from stdout
	rawJSON := strings.TrimSpace(stdoutBuf.String())
	if rawJSON == "" {
		if interrupted.Load() {
			// User interrupted with Ctrl+C — not an error
			return &InvokeResult{
				Envelope: types.Envelope{
					Status: "interrupted",
					Errors: []string{},
				},
				ExitCode: 130, // standard SIGINT exit code
			}, nil
		}
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "failed",
				Errors: []string{"Python process produced no output on stdout"},
			},
			ExitCode: exitCode,
		}, nil
	}

	var envelope types.Envelope
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		errs := []string{
			fmt.Sprintf("Failed to parse JSON output: %s", err),
			fmt.Sprintf("Raw output: %s", truncate(rawJSON, 500)),
		}
		if stdoutBuf.truncated {
			errs = append(errs, fmt.Sprintf(
				"Note: stdout exceeded %d bytes and was truncated to its tail; the JSON envelope may have been cut off",
				maxStdoutBytes))
		}
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "failed",
				Errors: errs,
			},
			ExitCode: exitCode,
		}, nil
	}

	if stdoutBuf.truncated {
		envelope.Warnings = append(envelope.Warnings, fmt.Sprintf(
			"Python stdout exceeded %d bytes; only the last %d bytes were retained (output truncated)",
			maxStdoutBytes, maxStdoutBytes))
	}

	return &InvokeResult{
		Envelope: envelope,
		ExitCode: exitCode,
	}, nil
}

// streamStderr reads stderr line by line and writes to os.Stderr.
// If quiet is true, stderr output is suppressed.
func streamStderr(r io.Reader, quiet bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if !quiet {
			fmt.Fprintln(os.Stderr, scanner.Text())
		}
	}
}

// setEnv sets or replaces an environment variable in a []string env slice.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// tailBuffer is an io.Writer that retains at most max bytes, keeping the
// most recent (tail) data — the JSON envelope is emitted last on stdout,
// so the tail is what matters. truncated records whether data was dropped.
type tailBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) >= t.max {
		t.buf = append(t.buf[:0], p[len(p)-t.max:]...)
		t.truncated = true
		return n, nil
	}
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		copy(t.buf, t.buf[over:])
		t.buf = t.buf[:t.max]
		t.truncated = true
	}
	return n, nil
}

func (t *tailBuffer) String() string {
	return string(t.buf)
}
