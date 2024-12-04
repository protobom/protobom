// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------
//go:build ignore
// +build ignore

package main

import (
	"log"
	"os"
	"path/filepath"
	"slices"
	"text/template"

	"github.com/protobom/protobom/pkg/sbom"
)

type templateData struct {
	Package string
	Names   []string
}

func main() {
	// Get the base file descriptor for the protobom message types.
	desc := sbom.NewDocument().ProtoReflect().Descriptor().ParentFile()
	data := templateData{Package: "sbom"}

	// Create a slice of protobom message type names.
	for idx := range desc.Messages().Len() {
		msg := desc.Messages().Get(idx)
		data.Names = append(data.Names, string(msg.Name()))
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("getting working directory: %v", err)
	}

	// Normalize behavior whether running directly or with `go generate`.
	if filepath.Base(cwd) == "api" {
		cwd = filepath.Dir(cwd)
	}

	slices.Sort(data.Names)
	tmplFile := filepath.Join(cwd, "api", "template", "value_scanner.go.tmpl")

	// Parse the template file.
	tmpl, err := template.ParseFiles(tmplFile)
	if err != nil {
		log.Fatalf("parsing template: %v", err)
	}

	// Create the target output file.
	output, err := os.Create(filepath.Join(cwd, "pkg", "sbom", "value_scanner.go"))
	if err != nil {
		log.Fatalf("creating output file: %v", err)
	}

	defer output.Close()

	// Execute the template and write result to target output file.
	if err := tmpl.Execute(output, data); err != nil {
		log.Fatalf("executing template: %v", err)
	}
}
