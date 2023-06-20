// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"fmt"
	"strings"
)

type Format string

const (
	JSON       = "json"
	TEXT       = "text"
	SPDX23TV   = Format("text/spdx+text;version=2.3")
	SPDX23JSON = Format("text/spdx+json;version=2.3")
	SPDX22TV   = Format("text/spdx+text;version=2.2")
	SPDX22JSON = Format("text/spdx+json;version=2.2")
	CDX13JSON  = Format("application/vnd.cyclonedx+json;version=1.3")
	CDX14JSON  = Format("application/vnd.cyclonedx+json;version=1.4")
	CDX15JSON  = Format("application/vnd.cyclonedx+json;version=1.5")

	CDXFORMAT  = "cyclonedx"
	SPDXFORMAT = "spdx"

	CDX_MIME  = "application/vnd.cyclonedx"
	SPDX_MIME = "text/spdx"

	CDX_VERSION_13   = "1.3"
	CDX_VERSION_14   = "1.4"
	CDX_VERSION_15   = "1.5"
	SPDX_VERSION_22  = "2.2"
	SPDX_VERSION_23  = "2.3"
	JSON_MIME_FORMAT = "json"
	XML_MIME_FORMAT  = "xml"
)

type Document interface{}

var List = []Format{SPDX23TV, SPDX23JSON, SPDX22TV, SPDX22JSON, CDX14JSON, CDX15JSON}
var ListFormatType = []string{CDXFORMAT, SPDXFORMAT}
var ListCdxVersion = []string{CDX_VERSION_13, CDX_VERSION_14, CDX_VERSION_15}
var ListSpdxVersion = []string{SPDX_VERSION_22, SPDX_VERSION_23}
var ListMimeFormat = []string{JSON_MIME_FORMAT, XML_MIME_FORMAT}
var MapVersion = map[string][]string{
	CDXFORMAT:  ListCdxVersion,
	SPDXFORMAT: ListSpdxVersion,
}

// Version returns the version of the format
func (f *Format) Version() string {
	parts := strings.Split(string(*f), ";version=")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func (f *Format) Major() string {
	ver := f.Version()
	parts := strings.Split(ver, ".")
	if len(parts) != 2 {
		return ""
	}

	return parts[0]
}

func (f *Format) Minor() string {
	ver := f.Version()
	parts := strings.Split(ver, ".")
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

// Encoding returns the encoding used by the SBOM format
func (f Format) Encoding() string {
	// Trim the version first
	switch {
	case strings.Contains(string(f), JSON):
		return JSON
	case strings.Contains(string(f), TEXT):
		return TEXT
	default:
		return ""
	}
}

// Type returns the encoding used by the SBOM format
func (f *Format) Type() string {
	if strings.Contains(string(*f), SPDXFORMAT) {
		return SPDXFORMAT
	} else if strings.Contains(string(*f), CDXFORMAT) {
		return CDXFORMAT
	}
	return ""
}

type FormatOpt struct {
	FormatType    string `yaml:"format-type,omitempty" json:"format-type,omitempty"`
	FormatVersion string `yaml:"format-version,omitempty" json:"format-version,omitempty"`
	MimeFormat    string `yaml:"mime-format,omitempty" json:"mime-format,omitempty"`
}

func (f *FormatOpt) Select() (Format, error) {
	var mimeUri string
	switch f.FormatType {
	case CDXFORMAT:
		mimeUri = CDX_MIME
	case SPDXFORMAT:
		mimeUri = SPDXFORMAT
	default:
		return Format(""), fmt.Errorf("unknown format type %s", f.FormatType)
	}

	formatSelect := Format(fmt.Sprintf("%s+%s;version=%s", mimeUri, f.MimeFormat, f.FormatVersion))
	found := false
	for _, known := range List {
		if known == formatSelect {
			found = true
		}
	}

	if !found {
		return Format(""), fmt.Errorf("unknown format selected %s", formatSelect)
	}

	return formatSelect, nil
}
