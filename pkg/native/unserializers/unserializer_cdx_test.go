package unserializers

import (
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/sbom"
)

const (
	cdxUnserializerTestVersion  = "1.5"
	cdxUnserializerTestEncoding = "json"
)

func TestCDXPhaseToSBOMType(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for phase, dtype := range map[cdx.LifecyclePhase]sbom.DocumentType_SBOMType{
		cdx.LifecyclePhaseBuild:        sbom.DocumentType_BUILD,
		cdx.LifecyclePhaseDecommission: sbom.DocumentType_DECOMISSION,
		cdx.LifecyclePhaseDesign:       sbom.DocumentType_DESIGN,
		cdx.LifecyclePhaseDiscovery:    sbom.DocumentType_DISCOVERY,
		cdx.LifecyclePhaseOperations:   sbom.DocumentType_DEPLOYED,
		cdx.LifecyclePhasePostBuild:    sbom.DocumentType_ANALYZED,
		cdx.LifecyclePhasePreBuild:     sbom.DocumentType_SOURCE,
	} {
		res := cdxu.phaseToSBOMType(&phase)
		require.Equal(t, dtype, *res)
	}
}

func TestComponentTypeToPurpose(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for compType, purpose := range map[cdx.ComponentType]sbom.Purpose{
		cdx.ComponentTypeApplication:          sbom.Purpose_APPLICATION,
		cdx.ComponentTypeFramework:            sbom.Purpose_FRAMEWORK,
		cdx.ComponentTypeLibrary:              sbom.Purpose_LIBRARY,
		cdx.ComponentTypeContainer:            sbom.Purpose_CONTAINER,
		cdx.ComponentTypePlatform:             sbom.Purpose_PLATFORM,
		cdx.ComponentTypeOS:                   sbom.Purpose_OPERATING_SYSTEM,
		cdx.ComponentTypeDevice:               sbom.Purpose_DEVICE,
		cdx.ComponentTypeDeviceDriver:         sbom.Purpose_DEVICE_DRIVER,
		cdx.ComponentTypeFirmware:             sbom.Purpose_FIRMWARE,
		cdx.ComponentTypeFile:                 sbom.Purpose_FILE,
		cdx.ComponentTypeMachineLearningModel: sbom.Purpose_MACHINE_LEARNING_MODEL,
		cdx.ComponentTypeData:                 sbom.Purpose_DATA,
		cdx.ComponentType("crap data"):        sbom.Purpose_UNKNOWN_PURPOSE,
	} {
		res := cdxu.componentTypeToPurpose(compType)
		require.Equal(t, purpose, res)
	}
}

func TestCdxHashAlgoToProtobomAlgo(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for c, p := range map[cdx.HashAlgorithm]sbom.HashAlgorithm{
		cdx.HashAlgoMD5:                      sbom.HashAlgorithm_MD5,
		cdx.HashAlgoSHA1:                     sbom.HashAlgorithm_SHA1,
		cdx.HashAlgoSHA256:                   sbom.HashAlgorithm_SHA256,
		cdx.HashAlgoSHA384:                   sbom.HashAlgorithm_SHA384,
		cdx.HashAlgoSHA512:                   sbom.HashAlgorithm_SHA512,
		cdx.HashAlgoSHA3_256:                 sbom.HashAlgorithm_SHA3_256,
		cdx.HashAlgoSHA3_384:                 sbom.HashAlgorithm_SHA3_384,
		cdx.HashAlgoSHA3_512:                 sbom.HashAlgorithm_SHA3_512,
		cdx.HashAlgoBlake2b_256:              sbom.HashAlgorithm_BLAKE2B_256,
		cdx.HashAlgoBlake2b_384:              sbom.HashAlgorithm_BLAKE2B_384,
		cdx.HashAlgoBlake2b_512:              sbom.HashAlgorithm_BLAKE2B_512,
		cdx.HashAlgoBlake3:                   sbom.HashAlgorithm_BLAKE3,
		cdx.HashAlgorithm("lskdjflksjdflkj"): sbom.HashAlgorithm_UNKNOWN,
	} {
		res := cdxu.cdxHashAlgoToProtobomAlgo(c)
		require.Equal(t, p, res)
	}
}

func TestCdxExtRefTypeToProtobomType(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for cdxRefType, protoType := range map[cdx.ExternalReferenceType]sbom.ExternalReference_ExternalReferenceType{
		cdx.ERTypeAttestation:                      sbom.ExternalReference_ATTESTATION,
		cdx.ERTypeBOM:                              sbom.ExternalReference_BOM,
		cdx.ERTypeBuildMeta:                        sbom.ExternalReference_BUILD_META,
		cdx.ERTypeBuildSystem:                      sbom.ExternalReference_BUILD_SYSTEM,
		cdx.ERTypeCertificationReport:              sbom.ExternalReference_CERTIFICATION_REPORT,
		cdx.ERTypeChat:                             sbom.ExternalReference_CHAT,
		cdx.ERTypeCodifiedInfrastructure:           sbom.ExternalReference_CODIFIED_INFRASTRUCTURE,
		cdx.ERTypeComponentAnalysisReport:          sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT,
		cdx.ExternalReferenceType("configuration"): sbom.ExternalReference_CONFIGURATION,
		cdx.ERTypeDistributionIntake:               sbom.ExternalReference_DISTRIBUTION_INTAKE,
		cdx.ERTypeDistribution:                     sbom.ExternalReference_DOWNLOAD,
		cdx.ERTypeDocumentation:                    sbom.ExternalReference_DOCUMENTATION,
		cdx.ERTypeDynamicAnalysisReport:            sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT,
		cdx.ExternalReferenceType("evidence"):      sbom.ExternalReference_EVIDENCE,
		cdx.ExternalReferenceType("formulation"):   sbom.ExternalReference_FORMULATION,
		cdx.ERTypeIssueTracker:                     sbom.ExternalReference_ISSUE_TRACKER,
		cdx.ERTypeLicense:                          sbom.ExternalReference_LICENSE,
		cdx.ExternalReferenceType("log"):           sbom.ExternalReference_LOG,
		cdx.ERTypeMailingList:                      sbom.ExternalReference_MAILING_LIST,
		cdx.ERTypeMaturityReport:                   sbom.ExternalReference_MATURITY_REPORT,
		cdx.ExternalReferenceType("model-card"):    sbom.ExternalReference_MODEL_CARD,
		cdx.ERTypeOther:                            sbom.ExternalReference_OTHER,
		cdx.ExternalReferenceType("poam"):          sbom.ExternalReference_POAM,
		cdx.ERTypeQualityMetrics:                   sbom.ExternalReference_QUALITY_METRICS,
		cdx.ERTypeReleaseNotes:                     sbom.ExternalReference_RELEASE_NOTES,
		cdx.ERTypeRiskAssessment:                   sbom.ExternalReference_RISK_ASSESSMENT,
		cdx.ERTypeRuntimeAnalysisReport:            sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT,
		cdx.ERTypeAdversaryModel:                   sbom.ExternalReference_SECURITY_ADVERSARY_MODEL,
		cdx.ERTypeAdvisories:                       sbom.ExternalReference_SECURITY_ADVISORY,
		cdx.ERTypeSecurityContact:                  sbom.ExternalReference_SECURITY_CONTACT,
		cdx.ERTypePentestReport:                    sbom.ExternalReference_SECURITY_PENTEST_REPORT,
		cdx.ERTypeThreatModel:                      sbom.ExternalReference_SECURITY_THREAT_MODEL,
		cdx.ERTypeSocial:                           sbom.ExternalReference_SOCIAL,
		cdx.ERTypeStaticAnalysisReport:             sbom.ExternalReference_STATIC_ANALYSIS_REPORT,
		cdx.ERTypeSupport:                          sbom.ExternalReference_SUPPORT,
		cdx.ERTypeVCS:                              sbom.ExternalReference_VCS,
		cdx.ERTypeVulnerabilityAssertion:           sbom.ExternalReference_VULNERABILITY_ASSERTION,
		cdx.ERTypeExploitabilityStatement:          sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT,
		cdx.ERTypeWebsite:                          sbom.ExternalReference_WEBSITE,
		cdx.ExternalReferenceType("kjlsd kosdkls"): sbom.ExternalReference_OTHER,
	} {
		res := cdxu.cdxExtRefTypeToProtobomType(cdxRefType)
		require.Equal(t, protoType, res)
	}
}

// findEdge returns true if the edge list has an edge of type et going from
// the from node to the to node.
func findEdge(edges []*sbom.Edge, et sbom.Edge_Type, from, to string) bool {
	for _, e := range edges {
		if e.Type == et && e.From == from && slices.Contains(e.To, to) {
			return true
		}
	}
	return false
}

func TestComponentScopeToEdge(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for name, tc := range map[string]struct {
		scope    cdx.Scope
		edgeType sbom.Edge_Type
		hasEdge  bool
	}{
		"required": {cdx.ScopeRequired, sbom.Edge_runtimeDependency, true},
		"optional": {cdx.ScopeOptional, sbom.Edge_optionalComponent, true},
		"excluded": {cdx.ScopeExcluded, sbom.Edge_devDependency, true},
		"absent":   {cdx.Scope(""), sbom.Edge_UNKNOWN, false},
		"unknown":  {cdx.Scope("not-a-scope"), sbom.Edge_UNKNOWN, false},
	} {
		t.Run(name, func(t *testing.T) {
			nl, err := cdxu.componentToNodeList(&cdx.Component{
				BOMRef: "parent",
				Type:   cdx.ComponentTypeApplication,
				Name:   "parent",
				Components: &[]cdx.Component{
					{
						BOMRef: "child",
						Type:   cdx.ComponentTypeLibrary,
						Name:   "child",
						Scope:  tc.scope,
					},
				},
			}, map[string]int{})
			require.NoError(t, err)

			// The structural relationship is always captured:
			require.True(t, findEdge(nl.Edges, sbom.Edge_contains, "parent", "child"))

			// The scope becomes an edge from the child to its parent:
			extraEdges := 0
			for _, e := range nl.Edges {
				if e.Type != sbom.Edge_contains {
					extraEdges++
				}
			}
			if tc.hasEdge {
				require.Equal(t, 1, extraEdges)
				require.True(t, findEdge(nl.Edges, tc.edgeType, "child", "parent"))
			} else {
				require.Equal(t, 0, extraEdges)
			}
		})
	}
}

func TestUnserializeComponentScope(t *testing.T) {
	data := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"component": {"bom-ref": "root", "type": "application", "name": "root"}
		},
		"components": [
			{"bom-ref": "opt", "type": "library", "name": "opt", "scope": "optional"},
			{"bom-ref": "excl", "type": "library", "name": "excl", "scope": "excluded"},
			{"bom-ref": "plain", "type": "library", "name": "plain"}
		]
	}`
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	doc, err := cdxu.Unserialize(strings.NewReader(data), nil, nil)
	require.NoError(t, err)

	// All top level components descend from the root node:
	for _, id := range []string{"opt", "excl", "plain"} {
		require.True(t, findEdge(doc.NodeList.Edges, sbom.Edge_contains, "root", id))
	}

	// The scoped components also relate back to the root node with their
	// scope relationship:
	require.True(t, findEdge(doc.NodeList.Edges, sbom.Edge_optionalComponent, "opt", "root"))
	require.True(t, findEdge(doc.NodeList.Edges, sbom.Edge_devDependency, "excl", "root"))

	// An absent scope produces no extra relationship:
	for _, e := range doc.NodeList.Edges {
		require.NotEqual(t, "plain", e.From)
	}
}

// TestDeterministicIds checks the identifiers generated for components that
// have no bom-ref: they are derived from the node's content, so they do not
// depend on where the component sits in the document, and identical
// components are told apart by their occurrence number in read order.
func TestDeterministicIds(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)

	parse := func(t *testing.T, sut *cdx.Component) []string {
		t.Helper()
		nodelist, err := cdxu.componentToNodeList(sut, map[string]int{})
		require.NoError(t, err)
		ids := make([]string, 0, len(nodelist.Nodes))
		for i := range nodelist.Nodes {
			ids = append(ids, nodelist.Nodes[i].Id)
		}
		return ids
	}

	t.Run("identical twins get occurrence suffixes", func(t *testing.T) {
		ids := parse(t, &cdx.Component{
			Type: "application",
			Components: &[]cdx.Component{
				{Type: "library"},
				{Type: "library"},
			},
		})
		require.Len(t, ids, 3)
		for _, id := range ids {
			require.True(t, strings.HasPrefix(id, "protobom-auto--"), id)
		}
		// The parent's content differs from the children's, the twins
		// share a checksum and are numbered apart:
		require.NotEqual(t, ids[0], ids[1])
		require.Equal(t, ids[1]+"-2", ids[2])
	})

	t.Run("explicit refs are preserved", func(t *testing.T) {
		ids := parse(t, &cdx.Component{
			Type: "application",
			Components: &[]cdx.Component{
				{BOMRef: "i-got-id", Type: "library"},
				{Type: "library"},
			},
		})
		require.Len(t, ids, 3)
		require.Equal(t, "i-got-id", ids[1])
		require.True(t, strings.HasPrefix(ids[2], "protobom-auto--"), ids[2])
	})

	t.Run("ids do not depend on position", func(t *testing.T) {
		library := cdx.Component{Type: "library", Name: "a-library"}
		alone := parse(t, &cdx.Component{
			Type:       "application",
			Components: &[]cdx.Component{library},
		})
		crowded := parse(t, &cdx.Component{
			Type: "application",
			Components: &[]cdx.Component{
				{BOMRef: "first", Type: "library", Name: "another"},
				library,
			},
		})
		require.Equal(t, alone[1], crowded[2])
	})
}

// TestUnserializeTools checks the reading of the document creation tools.
// Only the legacy tools array maps onto protobom's flat Tool; tools expressed
// as components or services are deliberately not read (see
// docs/tool-representation.md).
func TestUnserializeTools(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)

	t.Run("legacy tools array", func(t *testing.T) {
		doc, err := cdxu.Unserialize(strings.NewReader(`{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"version": 1,
			"metadata": {
				"tools": [
					{"vendor": "Anchore", "name": "syft", "version": "0.96.0"},
					{"name": "unversioned-tool"}
				]
			}
		}`), nil, nil)
		require.NoError(t, err)
		require.Equal(t, []*sbom.Tool{
			{Vendor: "Anchore", Name: "syft", Version: "0.96.0"},
			{Name: "unversioned-tool"},
		}, doc.Metadata.Tools)
	})

	t.Run("tool components and services are not read", func(t *testing.T) {
		doc, err := cdxu.Unserialize(strings.NewReader(`{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"version": 1,
			"metadata": {
				"tools": {
					"components": [
						{"type": "application", "name": "syft", "version": "1.2.0"}
					],
					"services": [
						{"name": "a-scanning-service"}
					]
				}
			}
		}`), nil, nil)
		require.NoError(t, err)
		require.Empty(t, doc.Metadata.Tools)
	})
}

func TestLicenseChoicesNilLicense(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for _, tc := range []struct {
		name     string
		licenses cdx.Licenses
	}{
		{
			name:     "empty license choice",
			licenses: cdx.Licenses{{}},
		},
		{
			name:     "nil license pointer with empty expression",
			licenses: cdx.Licenses{{License: nil, Expression: ""}},
		},
		{
			name:     "nil license mixed with a real id",
			licenses: cdx.Licenses{{}, {License: &cdx.License{ID: "MIT"}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A CycloneDX document can carry a license choice with no
			// license object at all (for example "licenses":[{}]). These
			// helpers must not dereference the nil License pointer.
			licenses := tc.licenses
			require.NotPanics(t, func() {
				cdxu.licenseChoicesToLicenseList(&licenses)
			})
			require.NotPanics(t, func() {
				cdxu.licenseChoicesToLicenseString(&licenses)
			})
		})
	}
}
