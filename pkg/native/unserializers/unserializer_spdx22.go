package unserializers

import (
	"github.com/protobom/protobom/pkg/native"
)

var _ native.Unserializer = &SPDX22{}

// SPDX22 parses SPDX 2.2 documents in JSON encoding. The tools-golang
// parser reads all SPDX 2.x versions and upgrades them to the 2.3
// model, so the document conversion is fully shared with the SPDX 2.3
// unserializer.
type SPDX22 struct {
	SPDX23
}

func NewSPDX22() *SPDX22 {
	return &SPDX22{}
}
