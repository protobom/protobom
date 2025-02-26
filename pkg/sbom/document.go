// The `sbom` package, provides the go data structures rendered from the format-agnostic representation of Software Bill of Materials data expressed in the protobom protocol buffer definitions.
//
// The protobom data model captures the SBOM data in a graph where the packages,
// components, files expressed in the native SBOM formats are `Nodes`, each related
// to each other through typed edges.
//
// A group of `Nodes` and `Edge`s form a `NodeList` which is the main work unit of
// protobom. A `NodeList` can be embedded in a `Document` to form a full
// representation of an SBOM.
//
// The SBOM package provides functions to work with the graph data through basic
// data operations like union, intersection and diffing as well as several querying
// functions to locate and extract information.
//
// Protobom documents can be created programmatically or ingested using the
// different unserializers that understand the native formats. Data from the
// neutral protobom representation can be rendered to native formats using
// serialzers.
package sbom

// NewDocument Creates a new empty document.
func NewDocument() *Document {
	return &Document{
		Metadata: &Metadata{
			Id:      "",
			Version: "1",
			Name:    "",
			// Date:    &timestamppb.New(spdxDoc.CreationInfo.Created), // bug in onesbom
			Tools:   []*Tool{},
			Authors: []*Person{},
		},
		NodeList: &NodeList{
			Nodes:        []*Node{},
			Edges:        []*Edge{},
			RootElements: []string{},
		},
	}
}

// GetRootNodes returns the top level nodes of the document. It calls the underlying
// method in the document's NodeList.
func (d *Document) GetRootNodes() []*Node {
	return d.NodeList.GetRootNodes()
}
