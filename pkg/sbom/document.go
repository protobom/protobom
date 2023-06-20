package sbom

// ToNodeList returns a nodelist containing the information in the document
func (d *Document) ToNodeList() *NodeList {
	return &NodeList{
		Nodes:        d.Nodes,
		Edges:        d.Edges,
		RootElements: d.RootElements,
	}
}

// GetRootNodes returns a list of pointers of the root nodes of the document
func (d *Document) GetRootNodes() []*Node {
	ret := []*Node{}
	index := rootElementsIndex{}
	for _, id := range d.RootElements {
		index[id] = struct{}{}
	}
	for i := range d.Nodes {
		if _, ok := index[d.Nodes[i].Id]; ok {
			ret = append(ret, d.Nodes[i])
			if len(ret) == len(index) {
				break
			}
		}
	}
	// TODO(ehandling): What if not all nodes were found?
	return ret
}
