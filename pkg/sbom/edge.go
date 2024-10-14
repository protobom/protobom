package sbom

import (
	"sort"
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
		To:   e.To,
	}
}

// PointsTo returns true if the edge is directed towards a specific node.
// It evaluates to true only if the edge includes the provided node ID in its list of To nodes.
func (e *Edge) PointsTo(id string) bool {
	for _, lid := range e.To {
		if lid == id {
			return true
		}
	}
	return false
}

// ToSPDX2 converts the edge type to the corresponding SPDX2 label.
// It maps the neutral edge type to its SPDX2 representation.
func (et Edge_Type) ToSPDX2() string {
	switch et {
	case Edge_UNKNOWN:
		return ""
	case Edge_AMENDS:
		return "AMENDS"
	case Edge_ANCESTOR:
		return "ANCESTOR_OF"
	case Edge_BUILD_DEPENDENCY:
		return "BUILD_DEPENDENCY_OF"
	case Edge_BUILD_TOOL:
		return "BUILD_TOOL_OF"
	case Edge_CONTAINS:
		return "CONTAINS"
	case Edge_CONTAINED_BY:
		return "CONTAINED_BY"
	case Edge_COPY:
		return "COPY_OF"
	case Edge_DATA_FILE:
		return "DATA_FILE_OF"
	case Edge_DEPENDENCY_MANIFEST:
		return "DEPENDENCY_MANIFEST_OF"
	case Edge_DEPENDS_ON:
		return "DEPENDS_ON"
	case Edge_DEPENDENCY_OF:
		return "DEPENDENCY_OF"
	case Edge_DESCENDANT:
		return "DESCENDANT_OF"
	case Edge_DESCRIBES:
		return "DESCRIBES"
	case Edge_DESCRIBED_BY:
		return "DESCRIBED_BY"
	case Edge_DEV_DEPENDENCY:
		return "DEV_DEPENDENCY_OF"
	case Edge_DEV_TOOL:
		return "DEV_TOOL_OF"
	case Edge_DISTRIBUTION_ARTIFACT:
		return "DISTRIBUTION_ARTIFACT"
	case Edge_DOCUMENTATION:
		return "DOCUMENTATION_OF"
	case Edge_DYNAMIC_LINK:
		return "DYNAMIC_LINK"
	case Edge_EXAMPLE:
		return "EXAMPLE_OF"
	case Edge_EXPANDED_FROM_ARCHIVE:
		return "EXPANDED_FROM_ARCHIVE"
	case Edge_FILE_ADDED:
		return "FILE_ADDED"
	case Edge_FILE_DELETED:
		return "FILE_DELETED"
	case Edge_FILE_MODIFIED:
		return "FILE_MODIFIED"
	case Edge_GENERATES:
		return "GENERATES"
	case Edge_GENERATED_FROM:
		return "GENERATED_FROM"
	case Edge_METAFILE:
		return "METAFILE_OF"
	case Edge_OPTIONAL_COMPONENT:
		return "OPTIONAL_COMPONENT_OF"
	case Edge_OPTIONAL_DEPENDENCY:
		return "OPTIONAL_DEPENDENCY_OF"
	case Edge_OTHER:
		return "OTHER"
	case Edge_PACKAGES:
		return "PACKAGE_OF"
	case Edge_PATCH:
		return "PATCH_APPLIED"
	case Edge_PREREQUISITE:
		return "HAS_PREREQUISITE"
	case Edge_PREREQUISITE_FOR:
		return "PREREQUISITE_FOR"
	case Edge_PROVIDED_DEPENDENCY:
		return "PROVIDED_DEPENDENCY_OF"
	case Edge_REQUIREMENT_FOR:
		return "REQUIREMENT_DESCRIPTION_FOR"
	case Edge_RUNTIME_DEPENDENCY:
		return "RUNTIME_DEPENDENCY_OF"
	case Edge_SPECIFICATION_FOR:
		return "SPECIFICATION_FOR"
	case Edge_STATIC_LINK:
		return "STATIC_LINK"
	case Edge_TEST:
		return "TEST_OF"
	case Edge_TEST_CASE:
		return "TEST_CASE_OF"
	case Edge_TEST_DEPENDENCY:
		return "TEST_DEPENDENCY_OF"
	case Edge_TEST_TOOL:
		return "TEST_TOOL_OF"
	case Edge_VARIANT:
		return "VARIANT_OF"
	default:
		return ""
	}
}

// EdgeTypeFromSPDX2 converts SPDX2 label in to the corresponding edge type.
// It maps the SPDX2 representation in to neutral edge type to its SPDX2 representation.
func EdgeTypeFromSPDX2(spdx2Type string) Edge_Type {
	spdx2Type = strings.ToUpper(spdx2Type)

	switch spdx2Type {
	case "AMENDS":
		return Edge_AMENDS
	case "ANCESTOR_OF":
		return Edge_ANCESTOR
	case "BUILD_DEPENDENCY_OF":
		return Edge_BUILD_DEPENDENCY
	case "BUILD_TOOL_OF":
		return Edge_BUILD_TOOL
	case "CONTAINED_BY":
		return Edge_CONTAINED_BY
	case "CONTAINS":
		return Edge_CONTAINS
	case "COPY_OF":
		return Edge_COPY
	case "DATA_FILE_OF":
		return Edge_DATA_FILE
	case "DEPENDENCY_MANIFEST_OF":
		return Edge_DEPENDENCY_MANIFEST
	case "DEPENDENCY_OF":
		return Edge_DEPENDENCY_OF
	case "DEPENDS_ON":
		return Edge_DEPENDS_ON
	case "DESCENDANT_OF":
		return Edge_DESCENDANT
	case "DESCRIBED_BY":
		return Edge_DESCRIBED_BY
	case "DESCRIBES":
		return Edge_DESCRIBES
	case "DEV_DEPENDENCY_OF":
		return Edge_DEV_DEPENDENCY
	case "DEV_TOOL_OF":
		return Edge_DEV_TOOL
	case "DISTRIBUTION_ARTIFACT":
		return Edge_DISTRIBUTION_ARTIFACT
	case "DOCUMENTATION_OF":
		return Edge_DOCUMENTATION
	case "DYNAMIC_LINK":
		return Edge_DYNAMIC_LINK
	case "EXAMPLE_OF":
		return Edge_EXAMPLE
	case "EXPANDED_FROM_ARCHIVE":
		return Edge_EXPANDED_FROM_ARCHIVE
	case "FILE_ADDED":
		return Edge_FILE_ADDED
	case "FILE_DELETED":
		return Edge_FILE_DELETED
	case "FILE_MODIFIED":
		return Edge_FILE_MODIFIED
	case "GENERATED_FROM":
		return Edge_GENERATED_FROM
	case "GENERATES":
		return Edge_GENERATES
	case "METAFILE_OF":
		return Edge_METAFILE
	case "OPTIONAL_COMPONENT_OF":
		return Edge_OPTIONAL_COMPONENT
	case "OPTIONAL_DEPENDENCY_OF":
		return Edge_OPTIONAL_DEPENDENCY
	case "OTHER":
		return Edge_OTHER
	case "PACKAGE_OF":
		return Edge_PACKAGES
	case "PATCH_APPLIED":
		return Edge_PATCH
	case "PATCH_FOR":
		return Edge_PATCH // TODO(degradation)
	case "PREREQUISITE_FOR":
		return Edge_PREREQUISITE_FOR
	case "HAS_PREREQUISITE":
		return Edge_PREREQUISITE
	case "PROVIDED_DEPENDENCY_OF":
		return Edge_PROVIDED_DEPENDENCY
	case "REQUIREMENT_DESCRIPTION_FOR":
		return Edge_REQUIREMENT_FOR
	case "RUNTIME_DEPENDENCY_OF":
		return Edge_RUNTIME_DEPENDENCY
	case "SPECIFICATION_FOR":
		return Edge_SPECIFICATION_FOR
	case "STATIC_LINK":
		return Edge_STATIC_LINK
	case "TEST_OF":
		return Edge_TEST
	case "TEST_CASE_OF":
		return Edge_TEST_CASE
	case "TEST_DEPENDENCY_OF":
		return Edge_TEST_DEPENDENCY
	case "TEST_TOOL_OF":
		return Edge_TEST_TOOL
	case "VARIANT_OF":
		return Edge_VARIANT
	default:
		return Edge_UNKNOWN
	}
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
	tos := e.To
	sort.Strings(tos)
	return e.From + ":" + e.Type.String() + ":" + strings.Join(tos, "+")
}

// AddDestinationById adds identifiers to the destination list of the edge. The
// new destination identifiers are guaranteed to be added only once and will
// not be duplicated if there is already a destination with the same ID.
func (e *Edge) AddDestinationById(ids ...string) {
	dests := map[string]struct{}{}
	for _, id := range e.To {
		dests[id] = struct{}{}
	}

	for _, id := range ids {
		if _, ok := dests[id]; ok {
			continue
		}
		dests[id] = struct{}{}
		e.To = append(e.To, id)
	}
}
