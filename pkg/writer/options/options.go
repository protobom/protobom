package options

import (
	"github.com/bom-squad/protobom/pkg/formats"
)

type Options struct {
	FormatOpt formats.FormatOpt `yaml:"format,omitempty" json:"format,omitempty"`
	Indent    int               `yaml:"indent,omitempty" json:"indent,omitempty"`
}

var Default = Options{
	Indent: 4,
	FormatOpt: formats.FormatOpt{
		FormatType:    formats.CDXFORMAT,
		FormatVersion: formats.CDX_VERSION_14,
		MimeFormat:    formats.JSON_MIME_FORMAT,
	},
}
