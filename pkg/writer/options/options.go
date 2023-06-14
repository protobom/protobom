package options

type Options struct {
	Format Format
	Indent int
}

var Default = Options{
	Indent: 4,
	Format: "application/vnd.cyclonedx+json;version=1.4",
}
