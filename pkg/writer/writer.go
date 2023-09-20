package writer

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
	drivers "github.com/bom-squad/protobom/pkg/native/serializers"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type Writer struct {
	RenderOptions   map[string]*native.RenderOptions
	SerialzeOptions map[string]*native.SerializeOptions
	Format          formats.Format
}

var (
	regMtx               sync.RWMutex
	serializers          = make(map[formats.Format]native.Serializer)
	defaultRenderOptions = &native.RenderOptions{
		CommonRenderOptions: native.CommonRenderOptions{
			Indent: 4,
		},
	}
	defaultSerializeOptions = &native.SerializeOptions{}
	defaultFormat           = formats.CDX15JSON
)

func New(opts ...WriterOption) *Writer {
	r := &Writer{
		RenderOptions:   make(map[string]*native.RenderOptions),
		SerialzeOptions: make(map[string]*native.SerializeOptions),
		Format:          defaultFormat,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func init() {
	regMtx.Lock()
	serializers[formats.CDX10JSON] = drivers.NewCDX("1.0", formats.JSON)
	serializers[formats.CDX11JSON] = drivers.NewCDX("1.1", formats.JSON)
	serializers[formats.CDX12JSON] = drivers.NewCDX("1.2", formats.JSON)
	serializers[formats.CDX13JSON] = drivers.NewCDX("1.3", formats.JSON)
	serializers[formats.CDX14JSON] = drivers.NewCDX("1.4", formats.JSON)
	serializers[formats.CDX15JSON] = drivers.NewCDX("1.5", formats.JSON)
	serializers[formats.SPDX23JSON] = drivers.NewSPDX23()
	regMtx.Unlock()
}

// RegisterSerializer registers a new serializer to handle writing serialized
// SBOMs in a specific format. When registerring a new serializer it replaces
// any other previously defined for the same format.
func RegisterSerializer(format formats.Format, s native.Serializer) {
	regMtx.Lock()
	serializers[format] = s
	regMtx.Unlock()
}

// UnregisterSerializer removes a serializer from the list of available
func UnregisterSerializer(format formats.Format) {
	regMtx.Lock()
	delete(serializers, format)
	regMtx.Unlock()
}

func GetFormatSerializer(format formats.Format) (native.Serializer, error) {
	if _, ok := serializers[format]; ok {
		return serializers[format], nil
	}
	return nil, fmt.Errorf("no serializer registered for %s", format)
}

func (w *Writer) WriteStreamWithOptions(bom *sbom.Document, wr io.WriteCloser, o *Options) error {
	if bom == nil {
		return fmt.Errorf("unable to write sbom to stream, SBOM is nil")
	}

	format := o.Format
	if o.Format == "" {
		format = w.Format
	}

	serializer, err := GetFormatSerializer(format)
	if err != nil {
		return fmt.Errorf("getting serializer for format %s: %w", format, err)
	}

	key := fmt.Sprintf("%T", serializer)

	so := o.SerializeOptions
	if so == nil {
		so = w.SerialzeOptions[key]
	}
	nativeDoc, err := serializer.Serialize(bom, so)
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	ro := o.RenderOptions
	if ro == nil {
		ro = w.RenderOptions[key]
	} else {
		fmt.Println("its empty!")
	}
	if err := serializer.Render(nativeDoc, wr, ro); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.WriteCloser) error {
	options, err := w.getOptions()
	if err != nil {
		return err
	}
	return w.WriteStreamWithOptions(bom, wr, options)
}

// WriteFile takes an sbom.Document and writes it to the file at path
func (w *Writer) WriteFileWithOptions(bom *sbom.Document, path string, o *Options) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.WriteStreamWithOptions(bom, f, o)
}

func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	options, err := w.getOptions()
	if err != nil {
		return err
	}
	return w.WriteFileWithOptions(bom, path, options)
}

func (w *Writer) getOptions() (*Options, error) {
	s, err := GetFormatSerializer(w.Format)
	if err != nil {
		return nil, err
	}

	ro := w.RenderOptions[fmt.Sprintf("%T", s)]
	if ro == nil {
		ro = defaultRenderOptions
	}

	so := w.SerialzeOptions[fmt.Sprintf("%T", s)]
	if so == nil {
		so = defaultSerializeOptions
	}

	return &Options{
		Format:           w.Format,
		RenderOptions:    ro,
		SerializeOptions: so,
	}, nil
}
