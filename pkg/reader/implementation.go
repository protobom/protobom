// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
	drivers "github.com/bom-squad/protobom/pkg/native/unserializers"
	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

var (
	regMtx        sync.RWMutex
	unserializers = make(map[formats.Format]native.Unserializer)
)

func init() {
	regMtx.Lock()
	unserializers[formats.CDX14JSON] = &drivers.UnserializerCDX14{}
	unserializers[formats.SPDX23JSON] = &drivers.UnserializerSPDX23{}
	regMtx.Unlock()
}

// RegisterUnserializer registers a new unserializer to parse a specific
// format. The new unserializer replaces any previously defined driver.
func RegisterUnserializer(format formats.Format, u native.Unserializer) {
	regMtx.Lock()
	unserializers[format] = u
	regMtx.Unlock()
}

//counterfeiter:generate . parserImplementation

type parserImplementation interface {
	OpenDocumentFile(string) (*os.File, error)
	DetectFormat(*options.Options, io.ReadSeeker) (formats.Format, error)
	GetUnserializer(*options.Options, formats.Format) (native.Unserializer, error)
	ParseStream(native.Unserializer, *options.Options, io.Reader) (*sbom.Document, error)
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
func (dpi *defaultParserImplementation) GetUnserializer(_ *options.Options, format formats.Format) (native.Unserializer, error) {
	if _, ok := unserializers[format]; ok {
		return unserializers[format], nil
	}

	return nil, fmt.Errorf("no format parser registered for %s", format)
}

func (dpi *defaultParserImplementation) ParseStream(formatParser native.Unserializer, opts *options.Options, f io.Reader) (*sbom.Document, error) {
	doc, err := formatParser.ParseStream(opts, f)
	if err != nil {
		return nil, fmt.Errorf("unserializing: %w", err)
	}
	return doc, nil
}
