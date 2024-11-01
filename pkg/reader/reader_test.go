package reader_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/nativefakes"
	"github.com/protobom/protobom/pkg/native/unserializers"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/reader/readerfakes"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/storage"
	"github.com/stretchr/testify/require"
)

// A note about Unserializers and reader behavior:
// Some of the tests in this file alter the loaded unserializers to use the fakes.
// If you want to write a test that requires a specific one, we recommend you to
// load it explicitly in the test, for example:
//
//   r := reader.New()
//   reader.RegisterUnserializer(formats.SPDX23JSON, unserializers.NewSPDX23())
//
// Failure to do so may result in varying behavior when the test is run
// by itself or in batch with the other tests.

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
	doc := sbom.NewDocument()
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
				format := formats.CDX16JSON
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
				fakeSniffer.SniffReaderReturns(formats.CDX16JSON, nil)
				fake.UnserializeReturns(nil, errors.New("parse error"))
				reader.RegisterUnserializer(formats.CDX16JSON, fake)
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
	doc := sbom.NewDocument()
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
				format := formats.CDX16JSON
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
	doc := sbom.NewDocument()
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
	doc := sbom.NewDocument()
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
				format := formats.CDX16JSON
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

func TestReaderSourceData(t *testing.T) {
	t.Parallel()
	data, err := base64.StdEncoding.DecodeString(
		"ewogICAgInNwZHhWZXJzaW9uIjogIlNQRFgtMi4zIiwKICAgICJkYXRhTGljZW5zZSI6ICJDQzAtMS4wIiwKICAgICJTUERYSUQiOiAiU1BEWFJlZi1ET0NVTUVOVCIsCiAgICAibmFtZSI6ICJ0ZXN0IiwKICAgICJkb2N1bWVudE5hbWVzcGFjZSI6ICJodHRwczovL3NwZHgub3JnL3NwZHhkb2NzL3Byb3RvYm9tL2U0MjBhYmQwLTUyZTgtNDY4OS1iMTYxLTBjMmMzNWVkYTRlYyIsCiAgICAiY3JlYXRpb25JbmZvIjogewogICAgICAgICJsaWNlbnNlTGlzdFZlcnNpb24iOiAiMy4yMCIsCiAgICAgICAgImNyZWF0b3JzIjogWwogICAgICAgICAgICAiVG9vbDogcHJvdG9ib20tZGV2ZWwiCiAgICAgICAgXSwKICAgICAgICAiY3JlYXRlZCI6ICIyMDI0LTEwLTI3VDE4OjMyOjAwWiIKICAgIH0sCiAgICAicGFja2FnZXMiOiBbCiAgICAgICAgewogICAgICAgICAgICAibmFtZSI6ICIiLAogICAgICAgICAgICAiU1BEWElEIjogIlNQRFhSZWYtMjRjYzkwNWYtZGE0YS00MDFkLThmMGUtNGIxYjI5MjQ2MjU5IiwKICAgICAgICAgICAgImRvd25sb2FkTG9jYXRpb24iOiAiTk9BU1NFUlRJT04iLAogICAgICAgICAgICAiZmlsZXNBbmFseXplZCI6IGZhbHNlLAogICAgICAgICAgICAiYW5ub3RhdGlvbnMiOiBbCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgImFubm90YXRvciI6ICJUb29sOiBwcm90b2JvbSAtIHYxLjAuMCIsCiAgICAgICAgICAgICAgICAgICAgImFubm90YXRpb25EYXRlIjogIjE5NzAtMDEtMDFUMDA6MDA6MDBaIiwKICAgICAgICAgICAgICAgICAgICAiYW5ub3RhdGlvblR5cGUiOiAiT1RIRVIiLAogICAgICAgICAgICAgICAgICAgICJjb21tZW50IjogIntcIm5hbWVcIjpcInRlc3QgQVwiLFwiZGF0YVwiOlwidGhpcyBpcyBkYXRhIEFcIn0iCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICJhbm5vdGF0b3IiOiAiVG9vbDogcHJvdG9ib20gLSB2MS4wLjAiLAogICAgICAgICAgICAgICAgICAgICJhbm5vdGF0aW9uRGF0ZSI6ICIxOTcwLTAxLTAxVDAwOjAwOjAwWiIsCiAgICAgICAgICAgICAgICAgICAgImFubm90YXRpb25UeXBlIjogIk9USEVSIiwKICAgICAgICAgICAgICAgICAgICAiY29tbWVudCI6ICJ7XCJuYW1lXCI6XCJ0ZXN0IEJcIixcImRhdGFcIjpcInRoaXMgaXMgdGhlIHNlY29uZCB2YWx1ZVwifSIKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgXQogICAgICAgIH0KICAgIF0sCiAgICAicmVsYXRpb25zaGlwcyI6IFsKICAgICAgICB7CiAgICAgICAgICAgICJzcGR4RWxlbWVudElkIjogIlNQRFhSZWYtRE9DVU1FTlQiLAogICAgICAgICAgICAicmVsYXRlZFNwZHhFbGVtZW50IjogIlNQRFhSZWYtMjRjYzkwNWYtZGE0YS00MDFkLThmMGUtNGIxYjI5MjQ2MjU5IiwKICAgICAgICAgICAgInJlbGF0aW9uc2hpcFR5cGUiOiAiREVTQ1JJQkVTIgogICAgICAgIH0KICAgIF0KfQo=",
	)
	require.NoError(t, err)
	br := bytes.NewReader(data)
	r := reader.New()
	// Explicitly register the real unserializer for spdx 2.3 as
	// some of the fakes may have been loaded by other tests.
	reader.RegisterUnserializer(formats.SPDX23JSON, unserializers.NewSPDX23())
	doc, err := r.ParseStreamWithOptions(br, &reader.Options{
		Format: formats.SPDX23JSON,
		UnserializeOptions: &native.UnserializeOptions{
			TrackSource: true,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "text/spdx+json;version=2.3", doc.Metadata.SourceData.Format)
	require.Len(t, doc.Metadata.SourceData.Hashes, 3)
	require.Equal(t, int64(1472), doc.Metadata.SourceData.Size)
	require.Equal(t, "2f48db1a89d5e7f8b2d4d1a412be14d932f5613f", doc.Metadata.SourceData.Hashes[int32(sbom.HashAlgorithm_SHA1)])
	require.Equal(t, "f042095476ef416fae33e9a76a4e406ff337cfc15a6f694894e6ff0070adb089", doc.Metadata.SourceData.Hashes[int32(sbom.HashAlgorithm_SHA256)])
	require.Equal(t, "71b04d63bc55dc78b91dfb376484a20a4e410fd58db893ed6e20637ccb495f7bf83b1aa76ab377bd9a6ef96d0d19f8cfa834d152dbf4880c2400be9a89dea429", doc.Metadata.SourceData.Hashes[int32(sbom.HashAlgorithm_SHA512)])
}
