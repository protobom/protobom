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
	DetectFormat(*options.Options, io.ReadSeeker) (formats.Format, error)   // Change string to format
	GetUnserializer(*options.Options, formats.Format) (Unserializer, error) // Change string to format
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) OpenDocumentFile(path string) (*os.File, error) {
	return os.Open(path)
}

func (dpi *defaultParserImplementation) DetectFormat(opts *options.Options, r io.ReadSeeker) (formats.Format, error) {
	sniffer := formats.Sniffer{}
	format, err := sniffer.SniffReader(r)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

func (dpi *defaultParserImplementation) GetUnserializer(_ *options.Options, format formats.Format) (Unserializer, error) {
	switch string(format) {
	case "text/spdx+json;version=2.3":
		return &UnserializerSPDX23{}, nil
	case "application/vnd.cyclonedx+json;version=1.4":
		return &UnserializerCDX14{}, nil
	default:
		return nil, fmt.Errorf("no format parser registered for %s", format)
	}
}
