package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

//counterfeiter:generate . Unserializer
type Unserializer interface {
	Unserialize(io.Reader, *UnserializeOptions, interface{}) (*sbom.Document, error)
}

type UnserializeOptions struct{}
