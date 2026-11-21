package sbom

import (
	"slices"
	"strings"
)

// NewEdge creates and returns a new graph edge.
func NewEdge() *Edge {
	return &Edge{
		To: []string{},
	}
}

// Copy returns a duplicate of the edge, including all connected graph edges.
func (e *Edge) Copy() *Edge {
	return &Edge{
		Type: e.Type,
		From: e.From,
		To:   slices.Clone(e.To),
	}
}

// PointsTo returns true if the edge is directed towards a specific node.
// It evaluates to true only if the edge includes the provided node ID in its list of To nodes.
func (e *Edge) PointsTo(id string) bool {
	return slices.Contains(e.To, id)
}

// Equal compares the current edge to another (e2) and returns true if they are identical.
// It checks if both edges have the same source, type, and destination nodes.
func (e *Edge) Equal(e2 *Edge) bool {
	if e2 == nil {
		return false
	}
	return e.flatString() == e2.flatString()
}

// flatString returns a serialized representation of the edge as a string,
// suitable for indexing or comparison of the contents of the current edge.
func (e *Edge) flatString() string {
	// The destinations are sorted on a copy. Two edges are equal whatever
	// order they list the same destinations in, but reading an edge must not
	// reorder the one being read: the order is what the document said, and
	// it is what gets written back out.
	tos := slices.Sorted(slices.Values(e.To))
	return e.From + ":" + e.Type.String() + ":" + strings.Join(tos, "+")
}

// AddDestinationById adds identifiers to the destination list of the edge. The
// new destination identifiers are guaranteed to be added only once and will
// not be duplicated if there is already a destination with the same ID.
func (e *Edge) AddDestinationById(ids ...string) {
	dests := e.indexDestinations()
	for _, id := range ids {
		if _, ok := dests[id]; ok {
			continue
		}
		dests[id] = struct{}{}
		e.To = append(e.To, id)
	}
}

// indexDestinations returns a set with the IDs of the destinations
func (e *Edge) indexDestinations() map[string]struct{} {
	dests := map[string]struct{}{}
	for _, id := range e.To {
		dests[id] = struct{}{}
	}
	return dests
}

// inverseEdgeTypes are the edge types that state their relationship from the
// owned node: the edge's source is the dependency, the part or the tool, and
// its destinations are what it belongs to.
var inverseEdgeTypes = map[Edge_Type]struct{}{
	Edge_amends:              {},
	Edge_buildDependency:     {},
	Edge_buildTool:           {},
	Edge_contained_by:        {},
	Edge_copy:                {},
	Edge_dataFile:            {},
	Edge_dependencyManifest:  {},
	Edge_dependencyOf:        {},
	Edge_describedBy:         {},
	Edge_devDependency:       {},
	Edge_devTool:             {},
	Edge_documentation:       {},
	Edge_example:             {},
	Edge_expandedFromArchive: {},
	Edge_fileAdded:           {},
	Edge_fileDeleted:         {},
	Edge_generatedFrom:       {},
	Edge_metafile:            {},
	Edge_optionalComponent:   {},
	Edge_optionalDependency:  {},
	Edge_packages:            {},
	Edge_patch:               {},
	Edge_prerequisiteFor:     {},
	Edge_providedDependency:  {},
	Edge_requirementFor:      {},
	Edge_runtimeDependency:   {},
	Edge_specificationFor:    {},
	Edge_test:                {},
	Edge_testCase:            {},
	Edge_testDependency:      {},
	Edge_testTool:            {},
	Edge_variant:             {},
}

// Inverse reports whether edges of the type run from the owned node to its
// owner. protobom keeps the relationship names and directions of SPDX 2,
// which states many of them that way round: "A DEPENDENCY_OF B", "A
// CONTAINED_BY B" and "A BUILD_TOOL_OF B" all name the owner last. Reading
// the graph as a tree, an inverse edge is followed backwards: its
// destinations are the parents and its source the child.
//
// These are the types the SPDX 3 serializer turns around, SPDX 3 having
// dropped the inverse relationships.
func (t Edge_Type) Inverse() bool {
	_, ok := inverseEdgeTypes[t]
	return ok
}

// EdgeGroup names a set of edge types that say the same kind of thing about
// a relationship, so they can be told apart or left out of a graph together
// (see WithoutEdgeGroups).
type EdgeGroup string

const (
	// EdgeGroupDevelopment are the dependencies and tools used to develop
	// the software.
	EdgeGroupDevelopment EdgeGroup = "development"
	// EdgeGroupTest are the dependencies, tools, tests and test cases used
	// to test the software.
	EdgeGroupTest EdgeGroup = "test"
	// EdgeGroupBuild are the dependencies and tools used to build the
	// software.
	EdgeGroupBuild EdgeGroup = "build"
	// EdgeGroupOptional are the components and dependencies the software
	// works without, and those it expects its environment to provide.
	EdgeGroupOptional EdgeGroup = "optional"
	// EdgeGroupDocumentation are the documentation and the examples of the
	// software.
	EdgeGroupDocumentation EdgeGroup = "documentation"
)

// edgeGroups lists the groups in the order EdgeGroups answers them, each
// with its edge types.
var edgeGroups = []struct {
	group EdgeGroup
	types []Edge_Type
}{
	{EdgeGroupDevelopment, []Edge_Type{Edge_devDependency, Edge_devTool}},
	{EdgeGroupTest, []Edge_Type{Edge_testDependency, Edge_testTool, Edge_test, Edge_testCase}},
	{EdgeGroupBuild, []Edge_Type{Edge_buildDependency, Edge_buildTool}},
	{EdgeGroupOptional, []Edge_Type{Edge_optionalDependency, Edge_optionalComponent, Edge_providedDependency}},
	{EdgeGroupDocumentation, []Edge_Type{Edge_documentation, Edge_example}},
}

// EdgeGroups returns every edge group, in a fixed order.
func EdgeGroups() []EdgeGroup {
	groups := make([]EdgeGroup, 0, len(edgeGroups))
	for _, g := range edgeGroups {
		groups = append(groups, g.group)
	}
	return groups
}

// EdgeTypes returns the edge types of the group. A group this package does
// not define has none.
func (g EdgeGroup) EdgeTypes() []Edge_Type {
	for _, eg := range edgeGroups {
		if eg.group == g {
			return slices.Clone(eg.types)
		}
	}
	return nil
}

// Group returns the group the edge type belongs to, or an empty group when
// it belongs to none: most types, a plain dependsOn or contains among them,
// say nothing a group captures.
func (t Edge_Type) Group() EdgeGroup {
	for _, eg := range edgeGroups {
		if slices.Contains(eg.types, t) {
			return eg.group
		}
	}
	return ""
}
