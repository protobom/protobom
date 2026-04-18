package cyclonedx

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/protobom/protobom/pkg/formats"
)

func ParseVersion(version string) (cyclonedx.SpecVersion, error) {
	var specVersion cyclonedx.SpecVersion
	switch version {
	case "1.0":
		specVersion = cyclonedx.SpecVersion1_0
	case "1.1":
		specVersion = cyclonedx.SpecVersion1_1
	case "1.2":
		specVersion = cyclonedx.SpecVersion1_2
	case "1.3":
		specVersion = cyclonedx.SpecVersion1_3
	case "1.4":
		specVersion = cyclonedx.SpecVersion1_4
	case "1.5":
		specVersion = cyclonedx.SpecVersion1_5
	case "1.6":
		specVersion = cyclonedx.SpecVersion1_6
	case "1.7":
		// cyclonedx-go does not yet support 1.7. Since 1.7 is additive
		// and protobom does not need any of the new fields, we parse
		// and serialize 1.7 documents using the 1.6 spec version.
		specVersion = cyclonedx.SpecVersion1_6
	default:
		return specVersion, fmt.Errorf("unsupported CDX version %s", version)
	}

	return specVersion, nil
}

func ParseEncoding(encoding string) (cyclonedx.BOMFileFormat, error) {
	var format cyclonedx.BOMFileFormat
	switch encoding {
	case formats.XML:
		format = cyclonedx.BOMFileFormatXML
	case formats.JSON:
		format = cyclonedx.BOMFileFormatJSON
	default:
		return format, fmt.Errorf("unsupported CDX encoding %s", encoding)
	}

	return format, nil
}
