package writer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	drivers "github.com/protobom/protobom/pkg/native/serializers"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/storage"
	fstore "github.com/protobom/protobom/pkg/storage"
)

type Writer struct {
	Storage storage.StoreRetriever
	Options *Options
}

var (
	serializers    sync.Map
	once           sync.Once
	defaultOptions = &Options{
		RenderOptions: &native.RenderOptions{
			Indent: 4,
		},
		SerializeOptions: &native.SerializeOptions{},
		StoreOptions:     &storage.StoreOptions{},
		formatOptions:    map[string]interface{}{},
	}
)

func New(opts ...WriterOption) *Writer {
	ensureSerializersInitialized()
	w := &Writer{
		Storage: fstore.NewFileSystem(),
		Options: defaultOptions,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func ensureSerializersInitialized() {
	once.Do(func() {
		serializers.Store(formats.CDX10JSON, drivers.NewCDX("1.0", formats.JSON))
		serializers.Store(formats.CDX11JSON, drivers.NewCDX("1.1", formats.JSON))
		serializers.Store(formats.CDX12JSON, drivers.NewCDX("1.2", formats.JSON))
		serializers.Store(formats.CDX13JSON, drivers.NewCDX("1.3", formats.JSON))
		serializers.Store(formats.CDX14JSON, drivers.NewCDX("1.4", formats.JSON))
		serializers.Store(formats.CDX15JSON, drivers.NewCDX("1.5", formats.JSON))
		serializers.Store(formats.SPDX23JSON, drivers.NewSPDX23())
	})
}

// RegisterSerializer adds a new serializer for the specified format.
func RegisterSerializer(format formats.Format, s native.Serializer) {
	ensureSerializersInitialized()
	serializers.Store(format, s)
}

// UnregisterSerializer removes a serializer for the specified format.
func UnregisterSerializer(format formats.Format) {
	ensureSerializersInitialized()
	serializers.Delete(format)
}

// GetFormatSerializer retrieves a serializer for the specified format.
// It ensures that serializers are initialized before attempting to load the serializer for the given format.
func GetFormatSerializer(format formats.Format) (native.Serializer, error) {
	ensureSerializersInitialized()
	if format == "" {
		return nil, errors.New("unable to find serializer, no format specified")
	}
	if serializer, ok := serializers.Load(format); ok {
		if serializer == nil {
			return nil, nil
		}
		return serializer.(native.Serializer), nil
	}
	return nil, fmt.Errorf("unable to find serializer for format %s", format)
}

// WriteStreamWithOptions writes an SBOM in a native format to the stream w using the options set o.
func (w *Writer) WriteStreamWithOptions(bom *sbom.Document, wr io.WriteCloser, o *Options) error {
	if bom == nil {
		return fmt.Errorf("unable to write sbom to stream, SBOM is nil")
	}

	format := o.Format
	if o.Format == "" {
		format = w.Options.Format
	}

	serializer, err := GetFormatSerializer(format)
	if err != nil {
		return fmt.Errorf("getting serializer: %w", err)
	}

	so := o.SerializeOptions
	if so == nil {
		so = defaultOptions.SerializeOptions
	}

	nativeDoc, err := serializer.Serialize(bom, so, o.GetFormatOptions(serializer))
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	ro := o.RenderOptions
	if ro == nil {
		ro = defaultOptions.RenderOptions
	}

	if err := serializer.Render(nativeDoc, wr, ro, o.GetFormatOptions(serializer)); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.WriteCloser) error {
	return w.WriteStreamWithOptions(bom, wr, w.Options)
}

// WriteFile takes an sbom.Document and writes it to the file at the specified
// path. If the file exists it will be truncated.
func (w *Writer) WriteFileWithOptions(bom *sbom.Document, path string, o *Options) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.WriteStreamWithOptions(bom, f, o)
}

// WriteFile
func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	return w.WriteFileWithOptions(
		bom, path, w.Options)
}

// Store persists a protobom document to disk using the default options
func (w *Writer) Store(bom *sbom.Document) error {
	return w.StoreWithOptions(bom, defaultOptions)
}

// StoreWithOptions stores a protobom document using the configured storage
// backend. This is the Store() variant that takes an options set.
func (w *Writer) StoreWithOptions(bom *sbom.Document, o *Options) error {
	if bom == nil {
		return fmt.Errorf("writing document")
	}

	if w.Storage == nil {
		return fmt.Errorf("no storage backend configured")
	}

	if err := w.Storage.Store(bom, o.StoreOptions); err != nil {
		return fmt.Errorf("calling backend store: %w", err)
	}

	return nil
}
