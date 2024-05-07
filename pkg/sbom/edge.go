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
	case Edge_amends:
		return "AMENDS"
	case Edge_ancestor:
		return "ANCESTOR_OF"
	case Edge_buildDependency:
		return "BUILD_DEPENDENCY_OF"
	case Edge_buildTool:
		return "BUILD_TOOL_OF"
	case Edge_contains:
		return "CONTAINS"
	case Edge_contained_by:
		return "CONTAINED_BY"
	case Edge_copy:
		return "COPY_OF"
	case Edge_dataFile:
		return "DATA_FILE_OF"
	case Edge_dependencyManifest:
		return "DEPENDENCY_MANIFEST_OF"
	case Edge_dependsOn:
		return "DEPENDS_ON"
	case Edge_dependencyOf:
		return "DEPENDENCY_OF"
	case Edge_descendant:
		return "DESCENDANT_OF"
	case Edge_describes:
		return "DESCRIBES"
	case Edge_describedBy:
		return "DESCRIBED_BY"
	case Edge_devDependency:
		return "DEV_DEPENDENCY_OF"
	case Edge_devTool:
		return "DEV_TOOL_OF"
	case Edge_distributionArtifact:
		return "DISTRIBUTION_ARTIFACT"
	case Edge_documentation:
		return "DOCUMENTATION_OF"
	case Edge_dynamicLink:
		return "DYNAMIC_LINK"
	case Edge_example:
		return "EXAMPLE_OF"
	case Edge_expandedFromArchive:
		return "EXPANDED_FROM_ARCHIVE"
	case Edge_fileAdded:
		return "FILE_ADDED"
	case Edge_fileDeleted:
		return "FILE_DELETED"
	case Edge_fileModified:
		return "FILE_MODIFIED"
	case Edge_generates:
		return "GENERATES"
	case Edge_generatedFrom:
		return "GENERATED_FROM"
	case Edge_metafile:
		return "METAFILE_OF"
	case Edge_optionalComponent:
		return "OPTIONAL_COMPONENT_OF"
	case Edge_optionalDependency:
		return "OPTIONAL_DEPENDENCY_OF"
	case Edge_other:
		return "OTHER"
	case Edge_packages:
		return "PACKAGE_OF"
	case Edge_patch:
		return "PATCH_APPLIED"
	case Edge_prerequisite:
		return "HAS_PREREQUISITE"
	case Edge_prerequisiteFor:
		return "PREREQUISITE_FOR"
	case Edge_providedDependency:
		return "PROVIDED_DEPENDENCY_OF"
	case Edge_requirementFor:
		return "REQUIREMENT_DESCRIPTION_FOR"
	case Edge_runtimeDependency:
		return "RUNTIME_DEPENDENCY_OF"
	case Edge_specificationFor:
		return "SPECIFICATION_FOR"
	case Edge_staticLink:
		return "STATIC_LINK"
	case Edge_test:
		return "TEST_OF"
	case Edge_testCase:
		return "TEST_CASE_OF"
	case Edge_testDependency:
		return "TEST_DEPENDENCY_OF"
	case Edge_testTool:
		return "TEST_TOOL_OF"
	case Edge_variant:
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
		return Edge_amends
	case "ANCESTOR_OF":
		return Edge_ancestor
	case "BUILD_DEPENDENCY_OF":
		return Edge_buildDependency
	case "BUILD_TOOL_OF":
		return Edge_buildTool
	case "CONTAINED_BY":
		return Edge_contained_by
	case "CONTAINS":
		return Edge_contains
	case "COPY_OF":
		return Edge_copy
	case "DATA_FILE_OF":
		return Edge_dataFile
	case "DEPENDENCY_MANIFEST_OF":
		return Edge_dependencyManifest
	case "DEPENDENCY_OF":
		return Edge_dependencyOf
	case "DEPENDS_ON":
		return Edge_dependsOn
	case "DESCENDANT_OF":
		return Edge_descendant
	case "DESCRIBED_BY":
		return Edge_describedBy
	case "DESCRIBES":
		return Edge_describes
	case "DEV_DEPENDENCY_OF":
		return Edge_devDependency
	case "DEV_TOOL_OF":
		return Edge_devTool
	case "DISTRIBUTION_ARTIFACT":
		return Edge_distributionArtifact
	case "DOCUMENTATION_OF":
		return Edge_documentation
	case "DYNAMIC_LINK":
		return Edge_dynamicLink
	case "EXAMPLE_OF":
		return Edge_example
	case "EXPANDED_FROM_ARCHIVE":
		return Edge_expandedFromArchive
	case "FILE_ADDED":
		return Edge_fileAdded
	case "FILE_DELETED":
		return Edge_fileDeleted
	case "FILE_MODIFIED":
		return Edge_fileModified
	case "GENERATED_FROM":
		return Edge_generatedFrom
	case "GENERATES":
		return Edge_generates
	case "METAFILE_OF":
		return Edge_metafile
	case "OPTIONAL_COMPONENT_OF":
		return Edge_optionalComponent
	case "OPTIONAL_DEPENDENCY_OF":
		return Edge_optionalDependency
	case "OTHER":
		return Edge_other
	case "PACKAGE_OF":
		return Edge_packages
	case "PATCH_APPLIED":
		return Edge_patch
	case "PATCH_FOR":
		return Edge_patch // TODO(degradation)
	case "PREREQUISITE_FOR":
		return Edge_prerequisiteFor
	case "HAS_PREREQUISITE":
		return Edge_prerequisite
	case "PROVIDED_DEPENDENCY_OF":
		return Edge_providedDependency
	case "REQUIREMENT_DESCRIPTION_FOR":
		return Edge_requirementFor
	case "RUNTIME_DEPENDENCY_OF":
		return Edge_runtimeDependency
	case "SPECIFICATION_FOR":
		return Edge_specificationFor
	case "STATIC_LINK":
		return Edge_staticLink
	case "TEST_OF":
		return Edge_test
	case "TEST_CASE_OF":
		return Edge_testCase
	case "TEST_DEPENDENCY_OF":
		return Edge_testDependency
	case "TEST_TOOL_OF":
		return Edge_testTool
	case "VARIANT_OF":
		return Edge_variant
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
