package writer

import (
	"bufio"
	"errors"
	"fmt"
	"testing"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/bom-squad/protobom/pkg/writer/writerfakes"
	"github.com/stretchr/testify/require"
)

type fakeWriteCloser struct {
	*bufio.Writer
}

func (fwc *fakeWriteCloser) Close() error {
	return nil
}

func TestWriteStream(t *testing.T) {
	synthError := errors.New("fake error")
	sut := &Writer{
		Options: options.Default,
	}
	for m, tc := range map[string]struct {
		prepare func(sut *Writer)
		mustErr bool
	}{
		"GetFormatSerializer fails": {
			prepare: func(sut *Writer) {
				impl := &writerfakes.FakeWriterImplementation{}
				impl.GetFormatSerializerReturns(nil, synthError)
				sut.impl = impl
			},
			mustErr: true,
		},
		"SerializeSBOM fails": {
			prepare: func(sut *Writer) {
				impl := &writerfakes.FakeWriterImplementation{}
				impl.SerializeSBOMReturns(synthError)
				sut.impl = impl
			},
			mustErr: true,
		},
		"success": {
			prepare: func(sut *Writer) {
				impl := &writerfakes.FakeWriterImplementation{}
				impl.SerializeSBOMReturns(nil)
				sut.impl = impl
			},
			mustErr: false,
		},
	} {
		tc.prepare(sut)
		err := sut.WriteStream(&sbom.Document{}, &fakeWriteCloser{})
		if tc.mustErr {
			require.Error(t, err, m)
		} else {
			require.NoError(t, err, m)
		}
	}

	// WriteStream with an empty SBOM must fail
	require.Error(t, sut.WriteStream(nil, &fakeWriteCloser{}), "empty SBOM")
}

func TestWriteFile(t *testing.T) {
	synthError := errors.New("fake error")
	sut := &Writer{
		Options: options.Default,
	}
	for m, tc := range map[string]struct {
		prepare func(sut *Writer)
		mustErr bool
	}{
		"OpenFile fails": {
			prepare: func(sut *Writer) {
				impl := &writerfakes.FakeWriterImplementation{}
				impl.OpenFileReturns(nil, synthError)
				sut.impl = impl
			},
			mustErr: true,
		},
		"success": {
			prepare: func(sut *Writer) {
				impl := &writerfakes.FakeWriterImplementation{}
				impl.OpenFileReturns(&fakeWriteCloser{}, nil)
				sut.impl = impl
			},
			mustErr: false,
		},
	} {
		tc.prepare(sut)
		err := sut.WriteFile(&sbom.Document{}, "/tmp/fake")
		if tc.mustErr {
			require.Error(t, err, m)
		} else {
			require.NoError(t, err, m)
		}
	}
}

func TestNew(t *testing.T) {
	n := New()
	require.NotNil(t, n)
	require.Equal(t, "*writer.Writer", fmt.Sprintf("%T", n))
}
