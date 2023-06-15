package options

import "github.com/bom-squad/protobom/pkg/format"

type Options struct {
	Format format.Format
	Indent int
}

var Default = Options{
	Indent: 4,
	Format: "application/vnd.cyclonedx+json;version=1.4",
}
