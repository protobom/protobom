package options

import "github.com/onesbom/onesbom/pkg/formats"

type Options struct {
	Format formats.Format
	Indent int
}

var Default = Options{
	Indent: 4,
	Format: "application/vnd.cyclonedx+json;version=1.4",
}
