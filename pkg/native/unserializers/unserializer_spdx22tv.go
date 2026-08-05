package unserializers

import (
	"github.com/protobom/protobom/pkg/native"
)

var _ native.Unserializer = &SPDX22TV{}

// SPDX22TV parses SPDX 2.2 documents in tag-value encoding. The
// tools-golang parser reads all SPDX 2.x versions and upgrades them to
// the 2.3 model, so the decoding and document conversion are fully
// shared with the SPDX 2.3 tag-value unserializer.
type SPDX22TV struct {
	SPDX23TV
}

func NewSPDX22TV() *SPDX22TV {
	return &SPDX22TV{}
}
