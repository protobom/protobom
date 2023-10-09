package writer_test

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
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

type dummyOptions struct {
	TestProperty string
}

func TestNew(t *testing.T) {
	fakeType := fmt.Sprintf("%T", &nativefakes.FakeSerializer{})
	tests := []struct {
		name   string
		format formats.Format
		ro     *native.RenderOptions
		so     *native.SerializeOptions
	}{
		{
			name:   "CDX format with 2 indent",
			format: formats.CDX15JSON,
			ro: &native.RenderOptions{
				CommonRenderOptions: native.CommonRenderOptions{
					Indent: 2,
				},
			},
			so: &native.SerializeOptions{},
		},
		{
			name:   "SPDX23 format with 4 indent and custom options",
			format: formats.SPDX23JSON,
			ro: &native.RenderOptions{
				CommonRenderOptions: native.CommonRenderOptions{
					Indent: 4,
				},
				Options: &dummyOptions{
					TestProperty: "test",
				},
			},
			so: &native.SerializeOptions{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			rom := map[string]*native.RenderOptions{
				fakeType: tt.ro,
			}

			som := map[string]*native.SerializeOptions{
				fakeType: tt.so,
			}

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(rom),
				writer.WithSerializeOptions(som),
			)
			r.NotNil(w)
			r.Equal(tt.format, w.Format)
			r.Equal(rom, w.RenderOptions)
		})
	}
}

func TestWriteStreamWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		bom     *sbom.Document
		prepare func(formats.Format)
		options *writer.Options
		wantErr bool
	}{
		{
			name:    "no option success",
			bom:     &sbom.Document{},
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{
				Format: formats.CDX14JSON,
			},
		},
		{
			name: "cdx 1.4 success",
			bom:  &sbom.Document{},
			prepare: func(_ formats.Format) {
				writer.RegisterSerializer(formats.CDX15JSON, &nativefakes.FakeSerializer{})
			},
			options: &writer.Options{},
		},
		{
			name:    "no bom fail",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{
				Format: formats.CDX15JSON,
			},
			wantErr: true,
		},
		{
			name: "invalid format error",
			bom:  &sbom.Document{},
			options: &writer.Options{
				Format: formats.Format("invalid"),
			},
			prepare: func(f formats.Format) {},
			wantErr: true,
		},
		{
			name: "render error",
			bom:  &sbom.Document{},
			options: &writer.Options{
				Format: formats.CDX15JSON,
			},
			prepare: func(f formats.Format) {
				s := &nativefakes.FakeSerializer{}
				s.RenderReturns(fmt.Errorf("render error"))
				writer.RegisterSerializer(f, s)
			},
			wantErr: true,
		},
		{
			name: "serializer error",
			bom:  &sbom.Document{},
			options: &writer.Options{
				Format: formats.CDX15JSON,
			},
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

			tt.prepare(tt.options.Format)

			w := writer.New()

			r.NotNil(w)

			err := w.WriteStreamWithOptions(tt.bom, &fakeWriteCloser{}, tt.options)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}
		})
	}
}

func TestWriteStream(t *testing.T) {
	bom := &sbom.Document{}
	fakeSerializer := &nativefakes.FakeSerializer{}
	fakeKey := fmt.Sprintf("%T", fakeSerializer)
	tests := []struct {
		name    string
		format  formats.Format
		ro      *native.RenderOptions
		so      *native.SerializeOptions
		prepare func(formats.Format)
		wantErr bool
	}{
		{
			name:    "default options success",
			prepare: func(_ formats.Format) { writer.RegisterSerializer(formats.CDX15JSON, fakeSerializer) },
		},
		{
			name:    "preconfigured options success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, fakeSerializer) },
			format:  formats.SPDX23JSON,
			ro: &native.RenderOptions{
				CommonRenderOptions: native.CommonRenderOptions{
					Indent: 100,
				},
			},
			so: &native.SerializeOptions{},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.format)

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(map[string]*native.RenderOptions{
					fakeKey: tt.ro,
				}),
				writer.WithSerializeOptions(map[string]*native.SerializeOptions{
					fakeKey: tt.so,
				}),
			)

			r.NotNil(w)

			err := w.WriteStream(bom, &fakeWriteCloser{})
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				if tt.ro != nil {
					_, _, a := fakeSerializer.RenderArgsForCall(i)
					r.Equal(tt.ro, a)

					_, b := fakeSerializer.SerializeArgsForCall(i)
					r.Equal(tt.so, b)
				}
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	bom := &sbom.Document{}
	fakeSerializer := &nativefakes.FakeSerializer{}
	fakeKey := fmt.Sprintf("%T", fakeSerializer)
	tests := []struct {
		name    string
		format  formats.Format
		ro      *native.RenderOptions
		so      *native.SerializeOptions
		prepare func(formats.Format)
		path    string
		wantErr bool
	}{
		{
			name: "default options success",
			prepare: func(f formats.Format) {
				format := f
				if f == "" {
					format = formats.CDX15JSON
				}
				writer.RegisterSerializer(format, fakeSerializer)
			},
			path: "test.json",
		},
		{
			name:    "preconfigured options success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, fakeSerializer) },
			format:  formats.SPDX23JSON,
			ro: &native.RenderOptions{
				CommonRenderOptions: native.CommonRenderOptions{
					Indent: 100,
				},
			},
			so:   &native.SerializeOptions{},
			path: "test.json",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.format)

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(map[string]*native.RenderOptions{
					fakeKey: tt.ro,
				}),
				writer.WithSerializeOptions(map[string]*native.SerializeOptions{
					fakeKey: tt.so,
				}),
			)

			file, err := os.Create(tt.path)
			defer func() {
				err := err
				if err == nil {
					os.Remove(file.Name())
				}
			}()

			r.NotNil(w)

			err = w.WriteFile(bom, tt.path)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				if tt.ro != nil {
					_, _, a := fakeSerializer.RenderArgsForCall(i)
					r.Equal(tt.ro, a)

					_, b := fakeSerializer.SerializeArgsForCall(i)
					r.Equal(tt.so, b)
				}
			}
		})
	}
}

func TestWriteFileWithOptions(t *testing.T) {
	bom := &sbom.Document{}

	tests := []struct {
		name    string
		path    string
		prepare func(formats.Format)
		options *writer.Options
		wantErr bool
	}{
		{
			name:    "valid format success",
			path:    "test.json",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{
				Format: formats.CDX15JSON,
			},
		},
		{
			name:    "invalid format error",
			prepare: func(f formats.Format) {},
			options: &writer.Options{
				Format: formats.Format("invalid"),
			},
			wantErr: true,
		},
		{
			name:    "invalid file path",
			path:    "",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{
				Format: formats.CDX15JSON,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.options.Format)

			w := writer.New(
				writer.WithFormat(tt.options.Format),
			)
			r.NotNil(w)

			file, err := os.Create(tt.path)
			defer func() {
				err := err
				if err == nil {
					os.Remove(file.Name())
				}
			}()

			err = w.WriteFileWithOptions(bom, tt.path, tt.options)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}
		})
	}
}

func TestSerializerRegistry(t *testing.T) {
	invalid := formats.Format("invalid")
	tests := []struct {
		name    string
		format  formats.Format
		wantErr bool
	}{
		{
			name:   "known format success",
			format: formats.CDX15JSON,
		},
		{
			name:   "new format success",
			format: formats.Format("new"),
		},
		{
			name:    "invalid format fail",
			format:  invalid,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			var serializer native.Serializer
			if tt.format != invalid {
				writer.RegisterSerializer(tt.format, serializer)
				defer writer.UnregisterSerializer(tt.format)
			}

			got, err := writer.GetFormatSerializer(tt.format)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.Equal(serializer, got)
				r.NoError(err)
			}
		})
	}
}
