package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

//counterfeiter:generate . Serializer
type Serializer interface {
	Serialize(doc *sbom.Document, options interface{}) (interface{}, error)
	Render(doc interface{}, writer io.Writer, options interface{}) error
}
