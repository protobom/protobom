package unserializers

import (
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

func TestDeterministicIds(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for _, tc := range []struct {
		name     string
		sut      *cdx.Component
		expected []string
		len      int
		mustErr  bool
	}{
		{
			name: "3 components",
			sut: &cdx.Component{
				Type: "application",
				Components: &[]cdx.Component{
					{Type: "library"},
					{Type: "library"},
				},
			},
			expected: []string{"protobom-auto--000000001", "protobom-auto--000000002", "protobom-auto--000000003"},
			len:      3,
			mustErr:  false,
		},
		{
			name: "3 components plus one with id",
			sut: &cdx.Component{
				Type: "application",
				Components: &[]cdx.Component{
					{BOMRef: "i-got-id", Type: "library"},
					{Type: "library"},
				},
			},
			expected: []string{"protobom-auto--000000001", "i-got-id", "protobom-auto--000000003"},
			len:      3,
			mustErr:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := 0
			nodelist, err := cdxu.componentToNodeList(tc.sut, &cc)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			names := []string{}
			require.Len(t, nodelist.Nodes, tc.len)
			for i := range nodelist.Nodes {
				names = append(names, nodelist.Nodes[i].Id)
			}
			require.Equal(t, tc.expected, names)
		})
	}
}

func TestCdxToolsToSBOMTools(t *testing.T) {
	cdxu := NewCDX(cdxUnserializerTestVersion, cdxUnserializerTestEncoding)
	for _, tc := range []struct {
		name     string
		sut      *cdx.ToolsChoice
		expected []*sbom.Tool
	}{
		{
			name:     "nil choice",
			sut:      nil,
			expected: []*sbom.Tool{},
		},
		{
			name: "legacy 1.4 array",
			sut: &cdx.ToolsChoice{
				Tools: &[]cdx.Tool{
					{Vendor: "CycloneDX", Name: "cyclonedx-gomod", Version: "v1.4.0"},
					{Name: "syft"},
				},
			},
			expected: []*sbom.Tool{
				{Name: "cyclonedx-gomod", Version: "v1.4.0", Vendor: "CycloneDX"},
				{Name: "syft"},
			},
		},
		{
			name: "1.5 components with vendor fallbacks",
			sut: &cdx.ToolsChoice{
				Components: &[]cdx.Component{
					// publisher wins
					{Name: "mikebom", Version: "1.0.0", Publisher: "Mike", Author: "ignored"},
					// manufacturer.name is next when publisher is empty
					{Name: "trivy", Version: "0.50.0", Manufacturer: &cdx.OrganizationalEntity{Name: "Aqua Security"}},
					// author is next
					{Name: "syft", Version: "1.0.0", Author: "anchore"},
					// group is the last resort
					{Name: "tool-x", Version: "2.0.0", Group: "acme"},
					// nothing populated leaves vendor empty
					{Name: "bare", Version: "3.0.0"},
				},
			},
			expected: []*sbom.Tool{
				{Name: "mikebom", Version: "1.0.0", Vendor: "Mike"},
				{Name: "trivy", Version: "0.50.0", Vendor: "Aqua Security"},
				{Name: "syft", Version: "1.0.0", Vendor: "anchore"},
				{Name: "tool-x", Version: "2.0.0", Vendor: "acme"},
				{Name: "bare", Version: "3.0.0"},
			},
		},
		{
			name: "1.5 services",
			sut: &cdx.ToolsChoice{
				Services: &[]cdx.Service{
					{Name: "scan-svc", Version: "1.2.3", Provider: &cdx.OrganizationalEntity{Name: "ProviderCo"}},
					{Name: "group-svc", Version: "0.1.0", Group: "grp"},
				},
			},
			expected: []*sbom.Tool{
				{Name: "scan-svc", Version: "1.2.3", Vendor: "ProviderCo"},
				{Name: "group-svc", Version: "0.1.0", Vendor: "grp"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cdxu.cdxToolsToSBOMTools(tc.sut)
			require.Len(t, got, len(tc.expected))
			for i := range tc.expected {
				require.Equal(t, tc.expected[i].GetName(), got[i].GetName())
				require.Equal(t, tc.expected[i].GetVersion(), got[i].GetVersion())
				require.Equal(t, tc.expected[i].GetVendor(), got[i].GetVendor())
			}
		})
	}
}

// TestCDXUnserializeMetadataTools exercises the full parse path (the exact
// symptom from the issue: GetMetadata().GetTools() coming back empty) for both
// the legacy 1.4 array and the 1.5+ component object forms.
func TestCDXUnserializeMetadataTools(t *testing.T) {
	for _, tc := range []struct {
		name     string
		doc      string
		expected []*sbom.Tool
	}{
		{
			name: "cdx 1.4 legacy tools array",
			doc: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"version": 1,
				"metadata": {
					"tools": [
						{"vendor": "CycloneDX", "name": "cyclonedx-gomod", "version": "v1.4.0"}
					]
				}
			}`,
			expected: []*sbom.Tool{
				{Name: "cyclonedx-gomod", Version: "v1.4.0", Vendor: "CycloneDX"},
			},
		},
		{
			name: "cdx 1.5 tools object with components",
			doc: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1,
				"metadata": {
					"tools": {
						"components": [
							{"type": "application", "name": "trivy", "version": "0.50.0", "manufacturer": {"name": "Aqua Security"}}
						]
					}
				}
			}`,
			expected: []*sbom.Tool{
				{Name: "trivy", Version: "0.50.0", Vendor: "Aqua Security"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cdxu := NewCDX("", cdxUnserializerTestEncoding)
			doc, err := cdxu.Unserialize(strings.NewReader(tc.doc), nil, nil)
			require.NoError(t, err)
			tools := doc.GetMetadata().GetTools()
			require.Len(t, tools, len(tc.expected))
			for i := range tc.expected {
				require.Equal(t, tc.expected[i].GetName(), tools[i].GetName())
				require.Equal(t, tc.expected[i].GetVersion(), tools[i].GetVersion())
				require.Equal(t, tc.expected[i].GetVendor(), tools[i].GetVendor())
			}
		})
	}
}
