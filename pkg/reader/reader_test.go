package reader_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/nativefakes"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/reader/readerfakes"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/storage"
	"github.com/stretchr/testify/require"
)

type fakeReadSeeker struct {
	io.Reader
}

func (f *fakeReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (f *fakeReadSeeker) Read(p []byte) (int, error) {
	return bytes.NewReader([]byte{}).Read(p)
}

func TestReader_ParseFile(t *testing.T) {
	fake := &nativefakes.FakeUnserializer{}
	fakeSniffer := &readerfakes.FakeSniffer{}
	doc := &sbom.Document{}
	tests := []struct {
		name    string
		path    string
		format  string
		uo      *native.UnserializeOptions
		prepare func()
		want    *sbom.Document
		wantErr bool
	}{
		{
			name: "happy success",
			path: "test-cdx",
			prepare: func() {
				format := formats.CDX15JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			want: doc,
		},
		{
			name: "custom options success",
			path: "test-spdx",
			prepare: func() {
				format := formats.SPDX23JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			uo:   &native.UnserializeOptions{},
			want: doc,
		},
		{
			name: "invalid format error",
			path: "test",
			prepare: func() {
				format := formats.Format("invalid")
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			wantErr: true,
		},
		{
			name:    "bad path error",
			path:    "",
			prepare: func() {},
			wantErr: true,
		},
		{
			name: "sniffer error",
			path: "test",
			prepare: func() {
				fakeSniffer.SniffReaderReturns("", errors.New("sniffer error"))
			},
			wantErr: true,
		},
		{
			name: "unserializer parse error",
			path: "test",
			prepare: func() {
				fakeSniffer.SniffReaderReturns(formats.CDX15JSON, nil)
				fake.UnserializeReturns(nil, errors.New("parse error"))
				reader.RegisterUnserializer(formats.CDX15JSON, fake)
			},
			wantErr: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			if tt.path != "" {
				_, err := os.Create(tt.path)
				r.NoError(err)

				defer func() {
					err := os.Remove(tt.path)
					if err != nil {
						t.Logf("failed to remove file: %v", err)
					}
				}()
			}

			tt.prepare()

			rdr := reader.New(
				reader.WithSniffer(fakeSniffer),
				reader.WithUnserializeOptions(&native.UnserializeOptions{}),
			)

			doc, err := rdr.ParseFile(tt.path)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				r.Equal(tt.want, doc)
				if tt.uo != nil {
					_, a, _ := fake.UnserializeArgsForCall(i)
					r.Equal(tt.uo, a)
				}
			}
		})
	}
}

func TestReader_ParseFileWithOptions(t *testing.T) {
	fake := &nativefakes.FakeUnserializer{}
	fakeSniffer := &readerfakes.FakeSniffer{}
	doc := &sbom.Document{}
	options := &reader.Options{
		UnserializeOptions: &native.UnserializeOptions{},
	}
	tests := []struct {
		name    string
		path    string
		options *reader.Options
		prepare func()
		want    *sbom.Document
		wantErr bool
	}{
		{
			name: "success",
			path: "test-cdx",
			prepare: func() {
				format := formats.CDX15JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			options: options,
			want:    doc,
		},
		{
			name:    "invalid path error",
			path:    "",
			prepare: func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			if tt.path != "" {
				_, err := os.Create(tt.path)
				r.NoError(err)

				defer func() {
					err := os.Remove(tt.path)
					if err != nil {
						t.Logf("failed to remove file: %v", err)
					}
				}()
			}

			tt.prepare()

			rdr := reader.New(
				reader.WithSniffer(fakeSniffer),
			)
			doc, err := rdr.ParseFileWithOptions(tt.path, options)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				r.Equal(tt.want, doc)
			}
		})
	}
}

func TestReader_ParseStreamWithOptions(t *testing.T) {
	fake := &nativefakes.FakeUnserializer{}
	fakeSniffer := &readerfakes.FakeSniffer{}
	doc := &sbom.Document{}
	options := &reader.Options{
		UnserializeOptions: &native.UnserializeOptions{},
	}
	tests := []struct {
		name    string
		options *reader.Options
		prepare func()
		want    *sbom.Document
		wantErr bool
	}{
		{
			name: "success",
			prepare: func() {
				format := formats.SPDX23JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			options: options,
			want:    doc,
		},
		{
			name: "invalid format error",
			prepare: func() {
				format := formats.Format("invalid")
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			options: options,
			wantErr: true,
		},
		{
			name: "sniffer error",
			prepare: func() {
				fakeSniffer.SniffReaderReturns("", errors.New("sniffer error"))
			},
			options: options,
			wantErr: true,
		},
		{
			name:    "nil options error",
			prepare: func() {},
			wantErr: true,
		},
		{
			name: "unserializer parse error",
			prepare: func() {
				format := formats.SPDX23JSON
				fakeSniffer.SniffReaderReturns(format, nil)
				fake.UnserializeReturns(nil, errors.New("parse error"))
				reader.RegisterUnserializer(format, fake)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare()

			rdr := reader.New(
				reader.WithSniffer(fakeSniffer),
			)
			doc, err := rdr.ParseStreamWithOptions(&fakeReadSeeker{}, tt.options)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				r.Equal(tt.want, doc)
			}
		})
	}
}

func TestReader_ParseStream(t *testing.T) {
	fake := &nativefakes.FakeUnserializer{}
	fakeSniffer := &readerfakes.FakeSniffer{}
	fakeKey := fmt.Sprintf("%T", fake)
	doc := &sbom.Document{}
	tests := []struct {
		name    string
		format  string
		prepare func()
		uo      *native.UnserializeOptions
		want    *sbom.Document
		wantErr bool
	}{
		{
			name: "default success",
			prepare: func() {
				format := formats.CDX15JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			want: doc,
		},
		{
			name: "custom options success",
			prepare: func() {
				format := formats.SPDX23JSON
				fake.UnserializeReturns(doc, nil)
				reader.RegisterUnserializer(format, fake)
				fakeSniffer.SniffReaderReturns(format, nil)
			},
			uo:   &native.UnserializeOptions{},
			want: doc,
		},
		{
			name: "options error",
			prepare: func() {
				fakeSniffer.SniffReaderReturns("", errors.New("sniffer error"))
			},
			wantErr: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			tt.prepare()

			rdr := reader.New(
				reader.WithSniffer(fakeSniffer),
				reader.WithUnserializeOptions(
					&native.UnserializeOptions{},
				),
				reader.WithFormatOptions(
					fakeKey, struct{}{},
				),
			)
			doc, err := rdr.ParseStream(&fakeReadSeeker{})
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
				r.Equal(tt.want, doc)
				if tt.uo != nil {
					_, a, _ := fake.UnserializeArgsForCall(i)
					r.Equal(tt.uo, a)
				}
			}
		})
	}
}

func TestUnserializerRegistry(t *testing.T) {
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

			var unserializer native.Unserializer
			if tt.format != invalid {
				reader.RegisterUnserializer(tt.format, unserializer)
				defer reader.UnregisterUnserializer(tt.format)
			}

			got, err := reader.GetFormatUnserializer(tt.format)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.Equal(unserializer, got)
				r.NoError(err)
			}
		})
	}
}

func TestRetrieve(t *testing.T) {
	t.Parallel()
	r := reader.New()
	r.Storage = &storage.Fake{}
	defaultOpts := &reader.Options{}

	for _, tc := range []struct {
		name    string
		opts    *reader.Options
		mustErr bool
		prepare func(r *reader.Reader)
	}{
		{
			name:    "no-errors",
			opts:    defaultOpts,
			mustErr: false,
			prepare: func(r *reader.Reader) {
				t.Helper()
				r.Storage.(*storage.Fake).RetrieveReturns = struct {
					Document *sbom.Document
					Error    error
				}{sbom.NewDocument(), nil}
			},
		},
		{
			name:    "no-backend",
			opts:    defaultOpts,
			mustErr: true,
			prepare: func(r *reader.Reader) {
				t.Helper()
				r.Storage = nil
			},
		},
		{
			name:    "retrieve-fails",
			opts:    defaultOpts,
			mustErr: true,
			prepare: func(r *reader.Reader) {
				t.Helper()
				r.Storage.(*storage.Fake).RetrieveReturns = struct {
					Document *sbom.Document
					Error    error
				}{nil, fmt.Errorf("fallo todo")}
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := *r
			tc.prepare(&r)
			doc, err := r.RetrieveWithOptions("test", tc.opts)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, doc)
		})
	}
}
