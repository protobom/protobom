package writer

import (
	"fmt"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/writer/options"
)

const (

	// SPDX Support
	SPDX_URI        = "text/spdx"
	SPDX_VERSION_22 = "2.2"
	SPDX_VERSION_23 = "2.3"

	// CycloneDX Support
	CDX_URI        = "application/vnd.cyclonedx"
	CDX_VERSION_13 = "1.3"
	CDX_VERSION_14 = "1.4"
	CDX_VERSION_15 = "1.5"

	JSON_ENCODING = "json"
	XML_ENCODING  = "xml"
	TEXT_ENCODING = "text"
)

var (
	AllEncoding = []string{JSON_ENCODING, XML_ENCODING, TEXT_ENCODING}
	Versions    = VersionGroups{
		formats.CDXFORMAT: {
			Versions:  []string{CDX_VERSION_13, CDX_VERSION_14, CDX_VERSION_15},
			Encodings: []string{JSON_ENCODING, XML_ENCODING},
			URI:       CDX_URI,
		},
		formats.SPDXFORMAT: {
			Versions:  []string{CDX_VERSION_13, CDX_VERSION_14, CDX_VERSION_15},
			Encodings: []string{JSON_ENCODING, TEXT_ENCODING},
			URI:       SPDX_URI,
		},
	}

	Default = Options{
		Type:     options.Default.Format.Type(),
		Version:  options.Default.Format.Version(),
		Encoding: options.Default.Format.Encoding(),
		URI:      options.Default.Format.URI(),
		Indent:   options.Default.Indent,
	}
)

type Options struct {
	Type     string `yaml:"format,omitempty" json:"format,omitempty"`
	Version  string `yaml:"version,omitempty" json:"version,omitempty"`
	Encoding string `yaml:"encoding,omitempty" json:"encoding,omitempty"`
	URI      string `yaml:"uri,omitempty" json:"uri,omitempty"`
	Indent   int    `yaml:"indent,omitempty" json:"indent,omitempty"`
}

func (f *Options) ToFormat() formats.Format {
	uri := f.URI

	// Autofill using supported formats.
	if uri == "" {
		uri = Versions.URI(f.Type)
	}

	return formats.Format(fmt.Sprintf("%s+%s;version=%s", uri, f.Encoding, f.Version))
}

func (f *Options) ToOptions() options.Options {
	return options.Options{
		Format: f.ToFormat(),
		Indent: f.Indent,
	}
}

func (f *Options) String() string {
	return string(f.ToFormat())
}

// Helper Object
type VersionGroup struct {
	Format    string
	URI       string
	Versions  []string
	Encodings []string
}

type VersionGroups map[string]VersionGroup

func (v VersionGroups) Versions(format string) []string {
	return v[format].Versions
}

func (v VersionGroups) Encodings(format string) []string {
	return v[format].Encodings
}

func (v VersionGroups) EncodingMap() map[string][]string {
	m := make(map[string][]string)
	for k := range v {
		m[k] = v.Encodings(k)
	}

	return m
}

func (v VersionGroups) URI(Type string) string {
	return v[Type].URI
}

func (v VersionGroups) VersionMap() map[string][]string {
	m := make(map[string][]string)
	for k := range v {
		m[k] = v.Versions(k)
	}

	return m
}

func (v VersionGroups) Formats() []string {
	var keys []string
	for k := range v {
		keys = append(keys, k)
	}

	return keys
}
