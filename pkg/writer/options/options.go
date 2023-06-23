package options

import (
	"github.com/bom-squad/protobom/pkg/formats"
)

type Options struct {
	Format formats.Format `yaml:"format,omitempty" json:"format,omitempty"`
	Indent int            `yaml:"indent,omitempty" json:"indent,omitempty"`
}

var Default = Options{
	Indent: 4,
	Format: formats.CDX14JSON,
}
