// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

// Command spdxconvert reads an SBOM and writes it back out as SPDX, in the
// version asked for. It exists for hack/verify-spdx.sh, which puts what
// protobom writes through the SPDX project's own tools.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/writer"
)

func main() {
	format := flag.String("format", "3.0.1", "SPDX version to write: 2.3 or 3.0.1")
	out := flag.String("out", "", "file to write to (required)")
	flag.Parse()

	if err := run(*format, *out, flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "spdxconvert: %v\n", err)
		os.Exit(1)
	}
}

func run(format, out string, args []string) error {
	if out == "" || len(args) != 1 {
		flag.Usage()
		return fmt.Errorf("one input file and -out are required")
	}

	var target formats.Format
	switch format {
	case "2.3":
		target = formats.SPDX23JSON
	case "3.0.1":
		target = formats.SPDX3JSON
	default:
		return fmt.Errorf("unknown SPDX version %q, want 2.3 or 3.0.1", format)
	}

	doc, err := reader.New().ParseFile(args[0])
	if err != nil {
		return fmt.Errorf("reading %s: %w", args[0], err)
	}

	file, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("creating %s: %w", out, err)
	}
	defer file.Close() //nolint:errcheck

	if err := writer.New().WriteStreamWithOptions(doc, file, &writer.Options{Format: target}); err != nil {
		return fmt.Errorf("writing %s: %w", out, err)
	}
	return nil
}
