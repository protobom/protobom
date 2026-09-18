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

import "slices"

const NamespaceUUID = `cea529d3-3fa2-4066-b5ac-e8717b8d374d`

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

// Absorb completes d with what d2 knows, without overriding anything d
// states. Metadata scalars d lacks (id, version, name, comment, date,
// source data) are filled from d2, and d2's tools, authors and document
// types that d does not list are appended. The node list absorbs d2's (see
// NodeList.Absorb): nodes present in both, by id, are merged entry by
// entry, and the rest of d2's nodes, edges and root elements are added.
func (d *Document) Absorb(d2 *Document) {
	if d2 == nil {
		return
	}
	if d.Metadata == nil {
		d.Metadata = &Metadata{}
	}
	if md := d2.GetMetadata(); md != nil {
		m := d.Metadata
		if m.Id == "" {
			m.Id = md.GetId()
		}
		if m.Version == "" {
			m.Version = md.GetVersion()
		}
		if m.Name == "" {
			m.Name = md.GetName()
		}
		if m.Comment == "" {
			m.Comment = md.GetComment()
		}
		if m.Date == nil {
			m.Date = md.GetDate()
		}
		if m.SourceData == nil {
			m.SourceData = md.GetSourceData()
		}
		for _, tool := range md.GetTools() {
			if !slices.ContainsFunc(m.GetTools(), func(t *Tool) bool { return t.flatString() == tool.flatString() }) {
				m.Tools = append(m.Tools, tool)
			}
		}
		for _, author := range md.GetAuthors() {
			if !slices.ContainsFunc(m.GetAuthors(), func(p *Person) bool { return p.flatString() == author.flatString() }) {
				m.Authors = append(m.Authors, author)
			}
		}
		for _, dt := range md.GetDocumentTypes() {
			if !slices.ContainsFunc(m.GetDocumentTypes(), func(t *DocumentType) bool { return t.flatString() == dt.flatString() }) {
				m.DocumentTypes = append(m.DocumentTypes, dt)
			}
		}
	}
	if d.NodeList == nil {
		d.NodeList = NewNodeList()
	}
	d.NodeList.Absorb(d2.GetNodeList())
}
