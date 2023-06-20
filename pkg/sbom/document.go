package sbom

// ToNodeList returns a nodelist containing the information in the document
func (d *Document) ToNodeList() *NodeList {
	return &NodeList{
		Nodes:        d.Nodes,
		Edges:        d.Edges,
		RootElements: d.RootElements,
	}
}
