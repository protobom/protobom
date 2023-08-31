// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader/options"
)

var (
	regMtx        sync.RWMutex
	unserializers = make(map[formats.Format]Unserializer)
)

func init() {
	regMtx.Lock()
	unserializers[formats.CDX14JSON] = &UnserializerCDX14{}
	unserializers[formats.SPDX23JSON] = &UnserializerSPDX23{}
	regMtx.Unlock()
}

// RegisterUnserializer registers a new unserializer to parse a specific
// format. The new unserializer replaces any previously defined driver.
func RegisterUnserializer(format formats.Format, u Unserializer) {
	regMtx.Lock()
	unserializers[format] = u
	regMtx.Unlock()
}

type parserImplementation interface {
	OpenDocumentFile(string) (*os.File, error)
	DetectFormat(*options.Options, io.ReadSeeker) (formats.Format, error)   // Change string to format
	GetUnserializer(*options.Options, formats.Format) (Unserializer, error) // Change string to format
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) OpenDocumentFile(path string) (*os.File, error) {
	return os.Open(path)
}

// DetectFormat reads from r and detects if the stream is a known SBOM format.
// If a known format is detected, it returns a format.Format, nil otherwise.
func (dpi *defaultParserImplementation) DetectFormat(opts *options.Options, r io.ReadSeeker) (formats.Format, error) {
	sniffer := formats.Sniffer{}
	format, err := sniffer.SniffReader(r)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

// GetUnserializer returns the registered unserializer for the specified format
func (dpi *defaultParserImplementation) GetUnserializer(_ *options.Options, format formats.Format) (Unserializer, error) {
	if _, ok := unserializers[format]; ok {
		return unserializers[format], nil
	}

	return nil, fmt.Errorf("no format parser registered for %s", format)
}
