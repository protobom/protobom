package sbom

func NewDocument() *Document {
	return &Document{
		Metadata: &Metadata{
			Id:      "",
			Version: "0",
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

// GetRootNodes returns the top level nodes of the document
func (d *Document) GetRootNodes() []*Node {
	return d.GetRootNodes()
}
