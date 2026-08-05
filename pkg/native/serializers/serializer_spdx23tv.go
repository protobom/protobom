package serializers

import (
	"errors"
	"fmt"
	"io"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"

	"github.com/protobom/protobom/pkg/native"
)

var _ native.Serializer = &SPDX23TV{}

// SPDX23TV serializes protobom documents to SPDX 2.3 in tag-value
// encoding. The conversion to the SPDX model is shared with the JSON
// serializer; only the rendering differs.
type SPDX23TV struct {
	SPDX23
}

func NewSPDX23TV() *SPDX23TV {
	return &SPDX23TV{}
}

// Render writes a serialized SPDX 2.3 document to the stream in
// tag-value encoding.
func (s *SPDX23TV) Render(doc any, wr io.Writer, _ *native.RenderOptions, _ any) error {
	spdxDoc, ok := doc.(*spdx.Document)
	if !ok {
		return errors.New("unable to cast doc as spdx.Document")
	}
	if err := tagvalue.Write(spdxDoc, wr); err != nil {
		return fmt.Errorf("writing SPDX tag-value: %w", err)
	}
	return nil
}
