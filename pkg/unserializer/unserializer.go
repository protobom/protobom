package unserializer

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bom-squad/protobom/pkg/sbom"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type CDXUnserializer interface {
	Metadata(*cdx.BOM) (*sbom.Metadata, *sbom.NodeList, error)
	NodeList(*cdx.Component) (*sbom.NodeList, error)
	Node(*cdx.Component) (*sbom.Node, error)
}

type SPDX23Unserializer interface {
	Metadata(*spdx23.Document) (*sbom.Metadata, *sbom.NodeList, error)
	NodeList(*spdx23.Document) (*sbom.NodeList, error)
	FileToNode(*spdx23.File) *sbom.Node
	PackageToNode(*spdx23.Package) *sbom.Node
}
