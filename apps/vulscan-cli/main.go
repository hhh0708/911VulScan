// 911VulScan CLI - LLM-powered static analysis security testing.
//
// This binary wraps the Python `vulscan` package, providing a native CLI
// experience with colored output, progress streaming, and JSON mode.
package main

import "github.com/hhh0708/911vulscan-cli/cmd"

func main() {
	cmd.Execute()
}
