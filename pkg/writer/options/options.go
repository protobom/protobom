package options

import "github.com/bom-squad/protobom/pkg/format"

type Options struct {
	Format format.Format
	Indent int
}

var Default = Options{
	Indent: 4,
	Format: formats.CDX14JSON,
}
