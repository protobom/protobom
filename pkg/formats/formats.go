// SPDX-FileCopyrightText: Copyright 2023 The OneSBOM Authors
// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"strings"
)

type Format string

const (
	JSON       = "json"
	XML        = "xml"
	TEXT       = "text"
	SPDX23TV   = Format("text/spdx+text;version=2.3")
	SPDX23JSON = Format("text/spdx+json;version=2.3")
	SPDX22TV   = Format("text/spdx+text;version=2.2")
	SPDX22JSON = Format("text/spdx+json;version=2.2")
	CDX10JSON  = Format("application/vnd.cyclonedx+json;version=1.0")
	CDX11JSON  = Format("application/vnd.cyclonedx+json;version=1.1")
	CDX12JSON  = Format("application/vnd.cyclonedx+json;version=1.2")
	CDX13JSON  = Format("application/vnd.cyclonedx+json;version=1.3")
	CDX14JSON  = Format("application/vnd.cyclonedx+json;version=1.4")
	CDX15JSON  = Format("application/vnd.cyclonedx+json;version=1.5")
	CDX16JSON  = Format("application/vnd.cyclonedx+json;version=1.6")
	CDXFORMAT  = "cyclonedx"
	SPDXFORMAT = "spdx"
)

type Document interface{}

var (
	ListFormats = []Format{CDXFORMAT, SPDXFORMAT}
	List        = []Format{SPDX23TV, SPDX23JSON, SPDX22TV, SPDX22JSON, CDX14JSON, CDX15JSON, CDX16JSON}
)

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

func (f *Format) URI() string {
	parts := strings.Split(string(*f), "+")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
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
