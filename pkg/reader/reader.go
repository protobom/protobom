// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

var defaultOptions = options.Options{}

type Reader struct {
	impl    parserImplementation
	Options options.Options
}

// New returns a new Reader with the default options
func New() *Reader {
	return &Reader{
		Options: defaultOptions,
		impl:    &defaultParserImplementation{},
	}
}

// ParseFile reads a file and returns an sbom.Document
func (r *Reader) ParseFile(path string) (*sbom.Document, error) {
	f, err := r.impl.OpenDocumentFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer f.Close()

	return r.ParseStream(f)
}

// ParseStream returns a document from a io reader
func (r *Reader) ParseStream(f io.ReadSeeker) (*sbom.Document, error) {
	format, err := r.impl.DetectFormat(&r.Options, f)
	if err != nil {
		return nil, fmt.Errorf("detecting SBOM format: %w", err)
	}

	formatParser, err := r.impl.GetUnserializer(&r.Options, format)
	if err != nil {
		return nil, fmt.Errorf("getting format parser: %w", err)
	}

	doc, err := formatParser.ParseStream(&r.Options, f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s document: %w", format, err)
	}

	return doc, err
}
