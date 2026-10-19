// Run with: go run functions.go /path/to/vohive > functions.jsonl
// Reads debug metadata only; never executes the target.
package main

import (
	"debug/elf"
	"debug/gosym"
	"encoding/json"
	"fmt"
	"os"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: go run functions.go TARGET")
	}
	file, err := elf.Open(os.Args[1])
	if err != nil {
		return err
	}
	defer file.Close()
	pcln, text := file.Section(".gopclntab"), file.Section(".text")
	if pcln == nil || text == nil {
		return fmt.Errorf("missing .gopclntab or .text")
	}
	data, err := pcln.Data()
	if err != nil {
		return err
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return err
	}
	out := json.NewEncoder(os.Stdout)
	for _, fn := range table.Funcs {
		source, line, _ := table.PCToLine(fn.Entry)
		if err := out.Encode(struct {
			Name   string `json:"name"`
			Entry  uint64 `json:"entry"`
			End    uint64 `json:"end"`
			Source string `json:"source"`
			Line   int    `json:"line"`
		}{fn.Name, fn.Entry, fn.End, source, line}); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
