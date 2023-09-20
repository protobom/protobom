package cdx

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bom-squad/protobom/pkg/formats"
)

func ParseVersion(version string) (cdx.SpecVersion, error) {
	var specVersion cdx.SpecVersion
	switch version {
	case "1.0":
		specVersion = cdx.SpecVersion1_0
	case "1.1":
		specVersion = cdx.SpecVersion1_1
	case "1.2":
		specVersion = cdx.SpecVersion1_2
	case "1.3":
		specVersion = cdx.SpecVersion1_3
	case "1.4":
		specVersion = cdx.SpecVersion1_4
	case "1.5":
		specVersion = cdx.SpecVersion1_5
	default:
		return specVersion, fmt.Errorf("unsupported CDX version %s", version)
	}

	return specVersion, nil
}

func ParseEncoding(encoding string) (cdx.BOMFileFormat, error) {
	var format cdx.BOMFileFormat
	switch encoding {
	case formats.XML:
		format = cdx.BOMFileFormatXML
	case formats.JSON:
		format = cdx.BOMFileFormatJSON
	default:
		return format, fmt.Errorf("unsupported CDX encoding %s", encoding)
	}

	return format, nil
}
