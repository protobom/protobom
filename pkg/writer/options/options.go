package options

import (
	"github.com/bom-squad/protobom/pkg/formats"
)

type Options struct {
	Format formats.Format
	Indent int
}

var Default = Options{
	Indent: 4,
	Format: formats.CDX14JSON,
}
