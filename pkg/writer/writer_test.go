package writer_test

import (
	"bufio"
	"fmt"
	"path"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/nativefakes"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/storage"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/stretchr/testify/require"
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
		fo     map[string]interface{}
	}{
		{
			name:   "CDX format with 2 indent",
			format: formats.CDX16JSON,
			ro: &native.RenderOptions{
				Indent: 2,
			},
			so: &native.SerializeOptions{},
		},
		{
			name:   "SPDX23 format with 4 indent and custom options",
			format: formats.SPDX23JSON,
			ro: &native.RenderOptions{
				Indent: 4,
			},
			so: &native.SerializeOptions{},
			fo: map[string]interface{}{
				string(formats.SPDX23JSON): &dummyOptions{
					TestProperty: "test",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(tt.ro),
				writer.WithSerializeOptions(tt.so),
				writer.WithFormatOptions(fakeType, tt.fo),
			)
			r.NotNil(w)
			r.Equal(tt.format, w.Options.Format)
			r.Equal(tt.ro, w.Options.RenderOptions)
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
			name:    "no format fail",
			bom:     &sbom.Document{},
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{},
			wantErr: true,
		},
		{
			name: "cdx 1.6 success",
			bom:  &sbom.Document{},
			prepare: func(_ formats.Format) {
				writer.RegisterSerializer(formats.CDX16JSON, &nativefakes.FakeSerializer{})
			},
			options: &writer.Options{
				Format: formats.CDX16JSON,
			},
		},
		{
			name:    "no bom fail",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, &nativefakes.FakeSerializer{}) },
			options: &writer.Options{
				Format: formats.CDX16JSON,
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
				Format: formats.CDX16JSON,
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
				Format: formats.CDX16JSON,
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
		fo      map[string]interface{}
		prepare func(formats.Format)
		wantErr bool
	}{
		{
			name:    "default options success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, fakeSerializer) },
			format:  formats.CDX16JSON,
		},
		{
			name:    "no format failure",
			prepare: func(_ formats.Format) {},
			wantErr: true,
		},
		{
			name:    "preconfigured options success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, fakeSerializer) },
			format:  formats.SPDX23JSON,
			ro: &native.RenderOptions{
				Indent: 100,
			},
			so: &native.SerializeOptions{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.format)

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(tt.ro),
				writer.WithSerializeOptions(tt.so),
				writer.WithFormatOptions(fakeKey, tt.fo),
			)

			r.NotNil(w)

			err := w.WriteStream(bom, &fakeWriteCloser{})
			if tt.wantErr {
				r.Error(err, "Format: "+w.Options.Format+" en tt: "+tt.format)
			} else {
				r.NoError(err)
				if tt.ro != nil {
					_, _, a, _ := fakeSerializer.RenderArgsForCall(fakeSerializer.RenderCallCount() - 1)
					r.Equal(tt.ro, a)

					_, b, _ := fakeSerializer.SerializeArgsForCall(fakeSerializer.SerializeCallCount() - 1)
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
		fo      map[string]interface{}
		prepare func(formats.Format)
		path    string
		wantErr bool
	}{
		{
			name: "default options success",
			prepare: func(f formats.Format) {
				format := f
				if f == "" {
					format = formats.CDX16JSON
				}
				writer.RegisterSerializer(format, fakeSerializer)
			},
			format: formats.CDX16JSON,
			path:   "test.json",
		},
		{
			name: "default options fail",
			prepare: func(f formats.Format) {
				format := f
				if f == "" {
					format = formats.CDX16JSON
				}
				writer.RegisterSerializer(format, fakeSerializer)
			},
			wantErr: true,
			path:    "test.json",
		},
		{
			name:    "preconfigured options success",
			prepare: func(f formats.Format) { writer.RegisterSerializer(f, fakeSerializer) },
			format:  formats.SPDX23JSON,
			ro: &native.RenderOptions{
				Indent: 100,
			},
			so:   &native.SerializeOptions{},
			path: "test.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare(tt.format)

			w := writer.New(
				writer.WithFormat(tt.format),
				writer.WithRenderOptions(tt.ro),
				writer.WithSerializeOptions(tt.so),
				writer.WithFormatOptions(fakeKey, tt.fo),
			)

			r.NotNil(w)

			tmpDir := t.TempDir()
			p := path.Join(tmpDir, tt.path)

			err := w.WriteFile(bom, p)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				if tt.ro != nil {
					_, _, a, _ := fakeSerializer.RenderArgsForCall(fakeSerializer.RenderCallCount() - 1)
					r.Equal(tt.ro, a)

					_, b, _ := fakeSerializer.SerializeArgsForCall(fakeSerializer.SerializeCallCount() - 1)
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
				Format: formats.CDX16JSON,
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
				Format: formats.CDX16JSON,
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

			tmpDir := t.TempDir()
			p := path.Join(tmpDir, tt.path)

			err := w.WriteFileWithOptions(bom, p, tt.options)
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
			format: formats.CDX16JSON,
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

func TestStore(t *testing.T) {
	t.Parallel()
	w := writer.New()
	w.Storage = &storage.Fake{}
	defaultOpts := &writer.Options{}

	for _, tc := range []struct {
		name    string
		opts    *writer.Options
		mustErr bool
		prepare func(w *writer.Writer)
	}{
		{
			name:    "no-errors",
			opts:    defaultOpts,
			mustErr: false,
			prepare: func(r *writer.Writer) {
				t.Helper()
				w.Storage.(*storage.Fake).StoreReturns = nil
			},
		},
		{
			name:    "no-backend",
			opts:    defaultOpts,
			mustErr: true,
			prepare: func(w *writer.Writer) {
				t.Helper()
				w.Storage = nil
			},
		},
		{
			name:    "retrieve-fails",
			opts:    defaultOpts,
			mustErr: true,
			prepare: func(w *writer.Writer) {
				t.Helper()
				w.Storage.(*storage.Fake).StoreReturns = fmt.Errorf("fallo todo")
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := *w
			tc.prepare(&w)
			err := w.StoreWithOptions(sbom.NewDocument(), tc.opts)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
