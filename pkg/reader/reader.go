// SPDX-FileCopyrightText: Copyright 2023 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package reader

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	drivers "github.com/protobom/protobom/pkg/native/unserializers"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/storage"
)

var (
	regMtx                    sync.RWMutex
	unserializers             = make(map[formats.Format]native.Unserializer)
	defaultUnserializeOptions = &native.UnserializeOptions{}
)

func init() {
	regMtx.Lock()
	unserializers[formats.CDX10JSON] = drivers.NewCDX("1.0", formats.JSON)
	unserializers[formats.CDX11JSON] = drivers.NewCDX("1.1", formats.JSON)
	unserializers[formats.CDX12JSON] = drivers.NewCDX("1.2", formats.JSON)
	unserializers[formats.CDX13JSON] = drivers.NewCDX("1.3", formats.JSON)
	unserializers[formats.CDX14JSON] = drivers.NewCDX("1.4", formats.JSON)
	unserializers[formats.CDX15JSON] = drivers.NewCDX("1.5", formats.JSON)
	unserializers[formats.SPDX23JSON] = drivers.NewSPDX23()
	regMtx.Unlock()
}

// RegisterUnserializer registers a new unserializer to parse a specific
// format. The new unserializer replaces any previously defined driver.
func RegisterUnserializer(format formats.Format, u native.Unserializer) {
	regMtx.Lock()
	unserializers[format] = u
	regMtx.Unlock()
}

// UnregisterUnserializer removes a serializer from the list of available
func UnregisterUnserializer(format formats.Format) {
	regMtx.Lock()
	delete(unserializers, format)
	regMtx.Unlock()
}

func GetFormatUnserializer(format formats.Format) (native.Unserializer, error) {
	if _, ok := unserializers[format]; ok {
		return unserializers[format], nil
	}
	return nil, fmt.Errorf("no serializer registered for %s", format)
}

type Reader struct {
	sniffer Sniffer
	Storage storage.StoreRetriever
	Options *Options
}

//counterfeiter:generate . Sniffer
type Sniffer interface {
	SniffReader(rs io.ReadSeeker) (formats.Format, error)
	SniffFile(path string) (formats.Format, error)
}

var defaultOptions = &Options{
	UnserializeOptions: defaultUnserializeOptions,
	formatOptions:      map[string]interface{}{},
}

func New(opts ...ReaderOption) *Reader {
	r := &Reader{
		sniffer: &formats.Sniffer{},
		Storage: storage.NewFileSystem(),
		Options: defaultOptions,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// ParseFile reads a file and returns an sbom.Document
func (r *Reader) ParseFile(path string) (*sbom.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer f.Close()

	return r.ParseStreamWithOptions(f, r.Options)
}

// ParseFile reads a file and returns an sbom.Document
func (r *Reader) ParseFileWithOptions(path string, o *Options) (*sbom.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer f.Close()

	return r.ParseStreamWithOptions(f, o)
}

// ParseStreamWithOptions returns a document from a ioreader, accept options for unserializer
func (r *Reader) ParseStreamWithOptions(f io.ReadSeeker, o *Options) (*sbom.Document, error) {
	if o == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	format := o.Format
	if o.Format == "" {
		f, err := r.detectFormat(f)
		if err != nil {
			return nil, fmt.Errorf("detecting SBOM format: %w", err)
		}
		format = f
	}

	unserializer, err := GetFormatUnserializer(format)
	if err != nil {
		return nil, fmt.Errorf("getting format parser: %w", err)
	}

	doc, err := unserializer.Unserialize(
		f, o.UnserializeOptions, r.Options.GetFormatOptions(unserializer),
	)
	if err != nil {
		return nil, fmt.Errorf("unserializing: %w", err)
	}

	return doc, err
}

// ParseStreamWithOptions returns a document from a ioreader
func (r *Reader) ParseStream(f io.ReadSeeker) (*sbom.Document, error) {
	return r.ParseStreamWithOptions(f, r.Options)
}

func (r *Reader) detectFormat(rs io.ReadSeeker) (formats.Format, error) {
	format, err := r.sniffer.SniffReader(rs)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

// Retrieve reads a document from the configured storage backend using the
// default options.
func (r *Reader) Retrieve(id string) (*sbom.Document, error) {
	return r.RetrieveWithOptions(id, defaultOptions)
}

// RetrieveWithOptions retrieves a document from the configured storage backend
// using a set of options.
func (r *Reader) RetrieveWithOptions(id string, o *Options) (*sbom.Document, error) {
	if id == "" {
		return nil, fmt.Errorf("unable to retrieve document, no document identifier specified")
	}

	if r.Storage == nil {
		return nil, fmt.Errorf("unable to retrieve document, no storage backend configured")
	}

	doc, err := r.Storage.Retrieve(id, o.RetrieveOptions)
	if err != nil {
		return nil, fmt.Errorf("calling backend store: %w", err)
	}

	return doc, nil
}
