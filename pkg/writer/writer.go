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
	Config *Config
}

var (
	regMtx        sync.RWMutex
	serializers   = make(map[formats.Format]native.Serializer)
	defaultConfig = &Config{
		RenderOptions: &DefaultRenderOptions{
			Indent: 4,
		},
		SerializeOptions: &DefaultSerializeOptions{},
	}
)

func New(opts ...WriterOption) *Writer {
	r := &Writer{
		Config: defaultConfig,
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

func (w *Writer) WriteStreamWithConfig(bom *sbom.Document, format formats.Format, config *Config, wr io.WriteCloser) error {
	if bom == nil {
		return fmt.Errorf("unable to write sbom to stream, SBOM is nil")
	}

	serializer, err := GetFormatSerializer(format)
	if err != nil {
		return fmt.Errorf("getting serializer for format %s: %w", format, err)
	}

	so := config.SerializeOptions
	if so == nil {
		so = w.Config.SerializeOptions
	}
	nativeDoc, err := serializer.Serialize(bom, so)
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	ro := config.RenderOptions
	if ro == nil {
		ro = w.Config.RenderOptions
	}
	if err := serializer.Render(nativeDoc, wr, ro); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

func (w *Writer) WriteStream(bom *sbom.Document, format formats.Format, wr io.WriteCloser) error {
	return w.WriteStreamWithConfig(bom, format, w.Config, wr)
}

// WriteFile takes an sbom.Document and writes it to the file at path
func (w *Writer) WriteFileWithConfig(bom *sbom.Document, format formats.Format, config *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.WriteStream(bom, format, f)
}

func (w *Writer) WriteFile(bom *sbom.Document, format formats.Format, path string) error {
	return w.WriteFileWithConfig(bom, format, w.Config, path)
}
