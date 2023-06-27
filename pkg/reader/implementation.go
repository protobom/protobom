// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"
	"os"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader/options"
)

type parserImplementation interface {
	OpenDocumentFile(string) (*os.File, error)
	DetectFormat(*options.Options, io.ReadSeeker) (formats.Format, error) // Change string to format
	GetParser(*options.Options, formats.Format) (Parser, error)           // Change string to format
}

type defaultParserImplementation struct{}

func (di *defaultParserImplementation) OpenDocumentFile(path string) (*os.File, error) {
	return os.Open(path)
}

func (di *defaultParserImplementation) DetectFormat(opts *options.Options, r io.ReadSeeker) (formats.Format, error) {
	sniffer := formats.Sniffer{}
	format, err := sniffer.SniffReader(r)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

func (dpi *defaultParserImplementation) GetParser(_ *options.Options, format formats.Format) (Parser, error) {
	switch string(format) {
	case "text/spdx+json;version=2.3":
		return &ParserSPDX23{}, nil
	//case "application/vnd.cyclonedx+json;version=1.4":
	//	return &FormatParserCDX14{}, nil
	default:
		return nil, fmt.Errorf("no format parser registered for %s", format)
	}
}
