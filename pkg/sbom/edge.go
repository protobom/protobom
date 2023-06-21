package sbom

// Copy returns a new edge with copies of all edges
func (e *Edge) Copy() *Edge {
	return &Edge{
		Type: e.Type,
		From: e.From,
		To:   e.To,
	}
}

// PointsTo returns true if an edge points to a node, in other words if it has
// id in its list of Tos
func (e *Edge) PointsTo(id string) bool {
	for _, lid := range e.To {
		if lid == id {
			return true
		}
	}
	return false
}

// ToSPDX2 converts the edge type to the corresponding SDPX2 label
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
