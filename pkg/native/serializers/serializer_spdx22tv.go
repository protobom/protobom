package serializers

import (
	"errors"
	"fmt"
	"io"

	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/tagvalue"

	"github.com/protobom/protobom/pkg/native"
)

var _ native.Serializer = &SPDX22TV{}

// SPDX22TV serializes protobom documents to SPDX 2.2 in tag-value
// encoding. The conversion to the SPDX 2.2 model is shared with the
// JSON serializer, only the rendering differs.
type SPDX22TV struct {
	SPDX22
}

func NewSPDX22TV() *SPDX22TV {
	return &SPDX22TV{}
}

// Render writes a serialized SPDX 2.2 document to the stream in
// tag-value encoding.
func (s *SPDX22TV) Render(doc any, wr io.Writer, _ *native.RenderOptions, _ any) error {
	doc22, ok := doc.(*v2_2.Document)
	if !ok {
		return errors.New("unable to cast doc as SPDX 2.2 document")
	}
	if err := tagvalue.Write(doc22, wr); err != nil {
		return fmt.Errorf("writing SPDX tag-value: %w", err)
	}
	return nil
}
