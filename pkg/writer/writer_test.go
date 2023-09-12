package writer_test

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native/nativefakes"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
)

type fakeWriteCloser struct {
	*bufio.Writer
}

func (fwc *fakeWriteCloser) Close() error {
	return nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		format formats.Format
		indent int
	}{
		{
			name:   "JSON format with 2 indent",
			format: formats.JSON,
			indent: 2,
		},
		{
			name:   "XML format with 4 indent",
			format: formats.XML,
			indent: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithIndent(tt.indent),
			)
			r.NotNil(w)
			r.Equal("*writer.Writer", fmt.Sprintf("%T", w))
			r.Equal(tt.format, w.Format)
			r.Equal(tt.indent, w.Indent)
		})
	}
}

func TestWriteStream(t *testing.T) {
	tests := []struct {
		name    string
		bom     *sbom.Document
		format  formats.Format
		indent  int
		prepare func(formats.Format)
		wantErr bool
	}{
		{
			name:    "cdx 1.4 success",
			bom:     &sbom.Document{},
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			format:  formats.CDX14JSON,
		},
		{
			name:    "no bom success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			format:  formats.CDX15JSON,
			wantErr: true,
		},
		{
			name:    "invalid format error",
			bom:     &sbom.Document{},
			format:  formats.Format("invalid"),
			prepare: func(f formats.Format) {},
			wantErr: true,
		},
		{
			name:   "render error",
			bom:    &sbom.Document{},
			format: formats.Format("invalid"),
			prepare: func(f formats.Format) {
				s := &nativefakes.FakeSerializer{}
				s.RenderReturns(fmt.Errorf("render error"))
				writer.RegisterSerializer(f, s)
			},
			wantErr: true,
		},
		{
			name:   "serializer error",
			bom:    &sbom.Document{},
			format: formats.Format("invalid"),
			prepare: func(f formats.Format) {
				s := &nativefakes.FakeSerializer{}
				s.SerializeReturns(nil, fmt.Errorf("serializer error"))
				writer.RegisterSerializer(f, s)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.format)

			w := writer.New(
				writer.WithFormat(tt.format),
			)

			r.NotNil(w)

			err := w.WriteStream(tt.bom, &fakeWriteCloser{})
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	bom := &sbom.Document{}

	tests := []struct {
		name           string
		format         formats.Format
		path           string
		mockSerializer bool
		wantErr        bool
	}{
		{
			name:           "valid format success",
			path:           "test.json",
			format:         formats.CDX15JSON,
			mockSerializer: true,
		},
		{
			name:    "invalid format error",
			format:  formats.Format("invalid"),
			wantErr: true,
		},
		{
			name:           "invalid file path",
			format:         formats.CDX15JSON,
			path:           "",
			mockSerializer: true,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			// register a fake serializer for the format
			if tt.mockSerializer {
				writer.RegisterSerializer(tt.format, &nativefakes.FakeSerializer{})
			}

			w := writer.New(
				writer.WithFormat(tt.format),
			)
			r.NotNil(w)

			file, err := os.Create(tt.path)
			defer func() {
				err := err
				if err == nil {
					os.Remove(file.Name())
				}
			}()

			err = w.WriteFile(bom, tt.path)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}
		})
	}
}
