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

// New creates a writer configured with the package defaults and the
// supplied options. Each writer gets its own copy of the defaults:
// WriterOptions mutate the writer's Options and, through its pointers,
// the nested option sets, so sharing the package defaults would leak one
// writer's configuration into every other writer in the process and race
// under concurrent construction.
func New(opts ...WriterOption) *Writer {
	ensureSerializersInitialized()
	w := &Writer{
		Storage: storage.NewFileSystem(),
		Options: defaultOptions.clone(),
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
		serializers.Store(formats.CDX16JSON, drivers.NewCDX("1.6", formats.JSON))
		serializers.Store(formats.CDX17JSON, drivers.NewCDX("1.7", formats.JSON))
		serializers.Store(formats.SPDX23JSON, drivers.NewSPDX23())
		serializers.Store(formats.SPDX3JSON, drivers.NewSPDX3())
		serializers.Store(formats.SPDX23TV, drivers.NewSPDX23TV())
		serializers.Store(formats.SPDX22JSON, drivers.NewSPDX22())
		serializers.Store(formats.SPDX22TV, drivers.NewSPDX22TV())
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
		s, ok := serializer.(native.Serializer)
		if !ok {
			return nil, fmt.Errorf("unable to cast serializer as native")
		}
		return s, nil
	}
	return nil, fmt.Errorf("unable to find serializer for format %s", format)
}

// WriteStreamWithOptions writes an SBOM in a native format to the stream w using the options set o.
func (w *Writer) WriteStreamWithOptions(bom *sbom.Document, wr io.Writer, o *Options) error {
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

	fo := w.formatOptions(o, serializer)
	nativeDoc, err := serializer.Serialize(bom, w.serializeOptions(o), fo)
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	ro := w.renderOptions(o)

	// Build the listening chain of all the I/O sinks
	sinks := []io.Writer{wr}
	for _, l := range o.Listeners {
		sinks = append(sinks, l)
	}
	stream := io.MultiWriter(sinks...)

	if err := serializer.Render(nativeDoc, stream, ro, fo); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

// serializeOptions resolves the serialize options for a call: the
// argument's when set, otherwise the writer's own. The package defaults
// are never handed out.
func (w *Writer) serializeOptions(o *Options) *native.SerializeOptions {
	if o != nil && o.SerializeOptions != nil {
		return o.SerializeOptions
	}
	if w.Options != nil && w.Options.SerializeOptions != nil {
		return w.Options.SerializeOptions
	}
	return &native.SerializeOptions{}
}

// renderOptions resolves the render options for a call the same way.
func (w *Writer) renderOptions(o *Options) *native.RenderOptions {
	if o != nil && o.RenderOptions != nil {
		return o.RenderOptions
	}
	if w.Options != nil && w.Options.RenderOptions != nil {
		return w.Options.RenderOptions
	}
	ro := *defaultOptions.RenderOptions
	return &ro
}

// formatOptions resolves the driver-specific options for a call: the
// argument's when it has any for the driver, otherwise the writer's own.
func (w *Writer) formatOptions(o *Options, driver native.Serializer) interface{} {
	if o != nil {
		if fo := o.GetFormatOptions(driver); fo != nil {
			return fo
		}
	}
	if w.Options != nil {
		return w.Options.GetFormatOptions(driver)
	}
	return nil
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.Writer) error {
	return w.WriteStreamWithOptions(bom, wr, w.Options)
}

// WriteFile takes an sbom.Document and writes it to the file at the specified
// path. If the file exists it will be truncated.
func (w *Writer) WriteFileWithOptions(bom *sbom.Document, path string, o *Options) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	return w.WriteStreamWithOptions(bom, f, o)
}

// WriteFile
func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	return w.WriteFileWithOptions(
		bom, path, w.Options)
}

// Store persists a protobom document using the configured storage backend
// and the writer's options (see WithStoreOptions).
func (w *Writer) Store(bom *sbom.Document) error {
	return w.StoreWithOptions(bom, w.Options)
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
