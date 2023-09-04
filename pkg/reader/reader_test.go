package reader

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/reader/readerfakes"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestParseStream(t *testing.T) {
	sut := &Reader{
		Options: options.Options{},
	}

	synthError := errors.New("fake error")
	fakereader := bytes.NewReader([]byte{})

	for m, tc := range map[string]struct {
		prepare func(*Reader)
		mustErr bool
	}{
		"DetectFormat fails": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.DetectFormatReturns("", synthError)
				r.impl = impl
			},
			mustErr: true,
		},
		"GetUnserializer fails": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.GetUnserializerReturns(nil, synthError)
				r.impl = impl
			},
			mustErr: true,
		},
		"ParseStream fails": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.ParseStreamReturns(nil, synthError)
				r.impl = impl
			},
			mustErr: true,
		},
		"Success": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.ParseStreamReturns(&sbom.Document{}, nil)
				r.impl = impl
			},
			mustErr: false,
		},
	} {
		tc.prepare(sut)
		doc, err := sut.ParseStream(fakereader)
		if tc.mustErr {
			require.Error(t, err, m)
		} else {
			require.NoError(t, err, m)
			require.NotNil(t, doc, m)
		}
	}
}

func TestParseFile(t *testing.T) {
	sut := &Reader{
		Options: options.Options{},
	}

	synthError := errors.New("fake error")

	for m, tc := range map[string]struct {
		prepare func(*Reader)
		mustErr bool
	}{
		"DetectFormat fails": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.OpenDocumentFileReturns(nil, synthError)
				r.impl = impl
			},
			mustErr: true,
		},
		"success": {
			prepare: func(r *Reader) {
				impl := &readerfakes.FakeParserImplementation{}
				impl.ParseStreamReturns(&sbom.Document{}, nil)
				r.impl = impl
			},
			mustErr: false,
		},
	} {
		tc.prepare(sut)
		doc, err := sut.ParseFile("/fake/path.json")
		if tc.mustErr {
			require.Error(t, err, m)
		} else {
			require.NoError(t, err, m)
			require.NotNil(t, doc, m)
		}
	}
}
