package reader

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
	drivers "github.com/bom-squad/protobom/pkg/native/unserializers"
	"github.com/bom-squad/protobom/pkg/sbom"
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
	sniffer            formats.Sniffer
	UnserializeOptions map[string]*native.UnserializeOptions
}

func New(opts ...ReaderOption) *Reader {
	r := &Reader{}

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

	options, err := r.getOptions(f)
	if err != nil {
		return nil, err
	}
	return r.ParseStreamWithOptions(f, options)
}

// ParseFile reads a file and returns an sbom.Document
func (r *Reader) ParseFileWithOptions(path string, o *Options) (*sbom.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer f.Close()

	return r.ParseStream(f)
}

// ParseStreamWithOptions returns a document from a ioreader, accept options for unserializer
func (r *Reader) ParseStreamWithOptions(f io.ReadSeeker, o *Options) (*sbom.Document, error) {
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

	doc, err := unserializer.Unserialize(f, &native.UnserializeOptions{})
	if err != nil {
		return nil, fmt.Errorf("unserializing: %w", err)
	}

	return doc, err
}

// ParseStreamWithOptions returns a document from a ioreader
func (r *Reader) ParseStream(f io.ReadSeeker) (*sbom.Document, error) {
	options, err := r.getOptions(f)
	if err != nil {
		return nil, err
	}
	return r.ParseStreamWithOptions(f, options)
}

func (r *Reader) detectFormat(rs io.ReadSeeker) (formats.Format, error) {
	format, err := r.sniffer.SniffReader(rs)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}

func (r *Reader) getOptions(f io.ReadSeeker) (*Options, error) {
	format, err := r.detectFormat(f)
	if err != nil {
		return nil, fmt.Errorf("detecting SBOM format: %w", err)
	}

	s, err := GetFormatUnserializer(format)
	if err != nil {
		return nil, err
	}

	uo := r.UnserializeOptions[fmt.Sprintf("%T", s)]
	if uo == nil {
		uo = defaultUnserializeOptions
	}

	return &Options{
		UnserializeOptions: uo,
	}, nil
}
