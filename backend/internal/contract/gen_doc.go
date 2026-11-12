//go:build ignore

// gen_doc writes docs/api/input-contract.md from the contract table. Run from this directory
// by `go generate ./internal/contract` (in backend/); TestDocMatchesTable fails on drift.
package main

import (
	"fmt"
	"os"

	"elyrn/internal/contract"
)

// docMode: the document is plain, world-readable text like every other file in docs/
const docMode = 0o644

func main() {
	if err := os.WriteFile(contract.DocPath, []byte(contract.Render()), docMode); err != nil {
		fmt.Fprintln(os.Stderr, "gen_doc:", err)
		os.Exit(1)
	}
}
