package serializers

import (
	"bytes"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

func TestComponentType(t *testing.T) {
	sut := CDX{}
	node := &sbom.Node{}

	for s, tc := range map[string]struct {
		prepare  func(*sbom.Node)
		compType cdx.ComponentType
	}{
		"node file": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FILE}
			n.Type = sbom.Node_FILE
		}, cdx.ComponentTypeFile},
		"node file, ne purpose": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_LIBRARY}
			n.Type = sbom.Node_FILE
		}, cdx.ComponentTypeFile},
		"application": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeApplication},
		"container": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_CONTAINER}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeContainer},
		"device": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_DEVICE}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeDevice},
		"library": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_LIBRARY}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeLibrary},
		"node package, pp file": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FILE}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeFile},
		"firmware": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FIRMWARE}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeFirmware},
		"framework": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FRAMEWORK}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeFramework},
		"operating-system": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_OPERATING_SYSTEM}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeOS},
		"data": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_DATA}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeData},
		"device-driver": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_DEVICE_DRIVER}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeDeviceDriver},
		"machine-learning-model": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_MACHINE_LEARNING_MODEL}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypeMachineLearningModel},
		"platform": {func(n *sbom.Node) {
			n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_PLATFORM}
			n.Type = sbom.Node_PACKAGE
		}, cdx.ComponentTypePlatform},
	} {
		tc.prepare(node)
		comp := sut.nodeToComponent(node)
		require.Equal(t, comp.Type, tc.compType, s)
	}
}

func TestNodeLicensesToComponent(t *testing.T) {
	sut := CDX{}
	for name, tc := range map[string]struct {
		licenses []string
		expected cdx.Licenses
	}{
		"single identifier": {
			licenses: []string{"Apache-2.0"},
			expected: cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
		},
		"or expression": {
			licenses: []string{"Apache-2.0 OR MIT"},
			expected: cdx.Licenses{{Expression: "Apache-2.0 OR MIT"}},
		},
		"and expression": {
			licenses: []string{"MIT AND BSD-3-Clause"},
			expected: cdx.Licenses{{Expression: "MIT AND BSD-3-Clause"}},
		},
		"with exception": {
			licenses: []string{"GPL-2.0-or-later WITH Classpath-exception-2.0"},
			expected: cdx.Licenses{{Expression: "GPL-2.0-or-later WITH Classpath-exception-2.0"}},
		},
		"grouped expression": {
			licenses: []string{"(MIT OR Apache-2.0) AND BSD-3-Clause"},
			expected: cdx.Licenses{{Expression: "(MIT OR Apache-2.0) AND BSD-3-Clause"}},
		},
		"identifier and expression": {
			licenses: []string{"MIT", "Apache-2.0 OR MIT"},
			expected: cdx.Licenses{
				{License: &cdx.License{ID: "MIT"}},
				{Expression: "Apache-2.0 OR MIT"},
			},
		},
		"reference minted from a name goes back to the name": {
			licenses: []string{"LicenseRef-x-protobom-GPL"},
			expected: cdx.Licenses{{License: &cdx.License{Name: "GPL"}}},
		},
		"reference from spdx is an expression": {
			licenses: []string{"LicenseRef-GPL"},
			expected: cdx.Licenses{{Expression: "LicenseRef-GPL"}},
		},
		"expression with a reference": {
			licenses: []string{"MIT OR LicenseRef-x-protobom-GPL"},
			expected: cdx.Licenses{{Expression: "MIT OR LicenseRef-x-protobom-GPL"}},
		},
		"listed identifier is written in its canonical spelling": {
			licenses: []string{"mit"},
			expected: cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
		},
		"deprecated identifier is still an identifier": {
			licenses: []string{"GPL-2.0"},
			expected: cdx.Licenses{{License: &cdx.License{ID: "GPL-2.0"}}},
		},
		"unlisted bare license is a name": {
			licenses: []string{"GPL"},
			expected: cdx.Licenses{{License: &cdx.License{Name: "GPL"}}},
		},
		"exception alone is not a license identifier": {
			licenses: []string{"Classpath-exception-2.0"},
			expected: cdx.Licenses{{License: &cdx.License{Name: "Classpath-exception-2.0"}}},
		},
	} {
		node := &sbom.Node{Licenses: tc.licenses}
		comp := sut.nodeToComponent(node)
		require.NotNil(t, comp.Licenses, name)
		require.Equal(t, tc.expected, *comp.Licenses, name)
	}
}

func TestEdgeTypeToScope(t *testing.T) {
	for edgeType, expected := range map[sbom.Edge_Type]cdx.Scope{
		sbom.Edge_runtimeDependency: cdx.ScopeRequired,
		sbom.Edge_optionalComponent: cdx.ScopeOptional,
		sbom.Edge_devDependency:     cdx.ScopeExcluded,
	} {
		scope, ok := edgeTypeToScope(edgeType)
		require.True(t, ok)
		require.Equal(t, expected, scope)
	}

	for _, edgeType := range []sbom.Edge_Type{
		sbom.Edge_contains, sbom.Edge_dependsOn, sbom.Edge_UNKNOWN,
	} {
		_, ok := edgeTypeToScope(edgeType)
		require.False(t, ok)
	}
}

func TestSerializeComponentScope(t *testing.T) {
	sut := NewCDX("1.5", "json")
	doc := &sbom.Document{
		Metadata: &sbom.Metadata{Version: "1"},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: "root", Name: "root"},
				{Id: "opt", Name: "opt"},
				{Id: "excl", Name: "excl"},
				{Id: "plain", Name: "plain"},
			},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: "root", To: []string{"opt", "excl", "plain"}},
				{Type: sbom.Edge_optionalComponent, From: "opt", To: []string{"root"}},
				{Type: sbom.Edge_devDependency, From: "excl", To: []string{"root"}},
			},
			RootElements: []string{"root"},
		},
	}

	res, err := sut.Serialize(doc, nil, nil)
	require.NoError(t, err)
	bom, ok := res.(*cdx.BOM)
	require.True(t, ok)

	// The scope relationships surface as the scope of the components:
	require.NotNil(t, bom.Components)
	scopes := map[string]cdx.Scope{}
	for _, c := range *bom.Components {
		scopes[c.BOMRef] = c.Scope
	}
	require.Equal(t, cdx.ScopeOptional, scopes["opt"])
	require.Equal(t, cdx.ScopeExcluded, scopes["excl"])
	require.Equal(t, cdx.Scope(""), scopes["plain"])

	// ... and must not leak into the dependency graph:
	require.NotNil(t, bom.Dependencies)
	for _, d := range *bom.Dependencies {
		require.NotEqual(t, "opt", d.Ref)
		require.NotEqual(t, "excl", d.Ref)
	}
}

func TestProtobomExtRefTypeToCdxType(t *testing.T) {
	cdxs := NewCDX("1.5", "json")
	for cdxRefType, protoType := range map[sbom.ExternalReference_ExternalReferenceType]cdx.ExternalReferenceType{
		sbom.ExternalReference_ATTESTATION:                             cdx.ERTypeAttestation,
		sbom.ExternalReference_BOM:                                     cdx.ERTypeBOM,
		sbom.ExternalReference_BUILD_META:                              cdx.ERTypeBuildMeta,
		sbom.ExternalReference_BUILD_SYSTEM:                            cdx.ERTypeBuildSystem,
		sbom.ExternalReference_CERTIFICATION_REPORT:                    cdx.ERTypeCertificationReport,
		sbom.ExternalReference_CHAT:                                    cdx.ERTypeChat,
		sbom.ExternalReference_CODIFIED_INFRASTRUCTURE:                 cdx.ERTypeCodifiedInfrastructure,
		sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT:               cdx.ERTypeComponentAnalysisReport,
		sbom.ExternalReference_CONFIGURATION:                           cdx.ExternalReferenceType("configuration"),
		sbom.ExternalReference_DISTRIBUTION_INTAKE:                     cdx.ERTypeDistributionIntake,
		sbom.ExternalReference_DOWNLOAD:                                cdx.ERTypeDistribution,
		sbom.ExternalReference_DOCUMENTATION:                           cdx.ERTypeDocumentation,
		sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT:                 cdx.ERTypeDynamicAnalysisReport,
		sbom.ExternalReference_EVIDENCE:                                cdx.ExternalReferenceType("evidence"),
		sbom.ExternalReference_FORMULATION:                             cdx.ExternalReferenceType("formulation"),
		sbom.ExternalReference_ISSUE_TRACKER:                           cdx.ERTypeIssueTracker,
		sbom.ExternalReference_LICENSE:                                 cdx.ERTypeLicense,
		sbom.ExternalReference_LOG:                                     cdx.ExternalReferenceType("log"),
		sbom.ExternalReference_MAILING_LIST:                            cdx.ERTypeMailingList,
		sbom.ExternalReference_MATURITY_REPORT:                         cdx.ERTypeMaturityReport,
		sbom.ExternalReference_MODEL_CARD:                              cdx.ExternalReferenceType("model-card"),
		sbom.ExternalReference_OTHER:                                   cdx.ERTypeOther,
		sbom.ExternalReference_POAM:                                    cdx.ExternalReferenceType("poam"),
		sbom.ExternalReference_QUALITY_METRICS:                         cdx.ERTypeQualityMetrics,
		sbom.ExternalReference_RELEASE_NOTES:                           cdx.ERTypeReleaseNotes,
		sbom.ExternalReference_RISK_ASSESSMENT:                         cdx.ERTypeRiskAssessment,
		sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT:                 cdx.ERTypeRuntimeAnalysisReport,
		sbom.ExternalReference_SECURITY_ADVERSARY_MODEL:                cdx.ERTypeAdversaryModel,
		sbom.ExternalReference_SECURITY_ADVISORY:                       cdx.ERTypeAdvisories,
		sbom.ExternalReference_SECURITY_CONTACT:                        cdx.ERTypeSecurityContact,
		sbom.ExternalReference_SECURITY_PENTEST_REPORT:                 cdx.ERTypePentestReport,
		sbom.ExternalReference_SECURITY_THREAT_MODEL:                   cdx.ERTypeThreatModel,
		sbom.ExternalReference_SOCIAL:                                  cdx.ERTypeSocial,
		sbom.ExternalReference_SOURCE_ARTIFACT:                         cdx.ERTypeSourceDistribution,
		sbom.ExternalReference_STATIC_ANALYSIS_REPORT:                  cdx.ERTypeStaticAnalysisReport,
		sbom.ExternalReference_SUPPORT:                                 cdx.ERTypeSupport,
		sbom.ExternalReference_VCS:                                     cdx.ERTypeVCS,
		sbom.ExternalReference_VULNERABILITY_ASSERTION:                 cdx.ERTypeVulnerabilityAssertion,
		sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT: cdx.ERTypeExploitabilityStatement,
		sbom.ExternalReference_WEBSITE:                                 cdx.ERTypeWebsite,
	} {
		res := cdxs.protobomExtRefTypeToCdxType(cdxRefType)
		require.Equal(t, protoType, res)
	}
}

func TestProtoHashAlgoToCdxAlgo(t *testing.T) {
	cdxs := NewCDX("1.5", "json")
	for protoAlgo, cdxAlgo := range map[sbom.HashAlgorithm]cdx.HashAlgorithm{
		sbom.HashAlgorithm_MD5:         cdx.HashAlgoMD5,
		sbom.HashAlgorithm_SHA1:        cdx.HashAlgoSHA1,
		sbom.HashAlgorithm_SHA256:      cdx.HashAlgoSHA256,
		sbom.HashAlgorithm_SHA384:      cdx.HashAlgoSHA384,
		sbom.HashAlgorithm_SHA512:      cdx.HashAlgoSHA512,
		sbom.HashAlgorithm_SHA3_256:    cdx.HashAlgoSHA3_256,
		sbom.HashAlgorithm_SHA3_384:    cdx.HashAlgoSHA3_384,
		sbom.HashAlgorithm_SHA3_512:    cdx.HashAlgoSHA3_512,
		sbom.HashAlgorithm_BLAKE2B_256: cdx.HashAlgoBlake2b_256,
		sbom.HashAlgorithm_BLAKE2B_384: cdx.HashAlgoBlake2b_384,
		sbom.HashAlgorithm_BLAKE2B_512: cdx.HashAlgoBlake2b_512,
		sbom.HashAlgorithm_BLAKE3:      cdx.HashAlgoBlake3,
	} {
		res, err := cdxs.protoHashAlgoToCdxAlgo(protoAlgo)
		require.NoError(t, err)
		require.Equal(t, cdxAlgo, res)

		_, err = cdxs.protoHashAlgoToCdxAlgo(sbom.HashAlgorithm(9999999))
		require.Error(t, err)
	}
}

func TestPurposeToComponentType(t *testing.T) {
	cdxs := NewCDX("1.5", "json")
	for protoPupose, cdxType := range map[sbom.Purpose]cdx.ComponentType{
		sbom.Purpose_APPLICATION:            cdx.ComponentTypeApplication,
		sbom.Purpose_EXECUTABLE:             cdx.ComponentTypeApplication,
		sbom.Purpose_INSTALL:                cdx.ComponentTypeApplication,
		sbom.Purpose_CONTAINER:              cdx.ComponentTypeContainer,
		sbom.Purpose_DATA:                   cdx.ComponentTypeData,
		sbom.Purpose_BOM:                    cdx.ComponentTypeData,
		sbom.Purpose_CONFIGURATION:          cdx.ComponentTypeData,
		sbom.Purpose_DOCUMENTATION:          cdx.ComponentTypeData,
		sbom.Purpose_EVIDENCE:               cdx.ComponentTypeData,
		sbom.Purpose_MANIFEST:               cdx.ComponentTypeData,
		sbom.Purpose_REQUIREMENT:            cdx.ComponentTypeData,
		sbom.Purpose_SPECIFICATION:          cdx.ComponentTypeData,
		sbom.Purpose_TEST:                   cdx.ComponentTypeData,
		sbom.Purpose_OTHER:                  cdx.ComponentTypeData,
		sbom.Purpose_DEVICE:                 cdx.ComponentTypeDevice,
		sbom.Purpose_DEVICE_DRIVER:          cdx.ComponentTypeDeviceDriver,
		sbom.Purpose_FILE:                   cdx.ComponentTypeFile,
		sbom.Purpose_PATCH:                  cdx.ComponentTypeFile,
		sbom.Purpose_SOURCE:                 cdx.ComponentTypeFile,
		sbom.Purpose_ARCHIVE:                cdx.ComponentTypeFile,
		sbom.Purpose_FIRMWARE:               cdx.ComponentTypeFirmware,
		sbom.Purpose_FRAMEWORK:              cdx.ComponentTypeFramework,
		sbom.Purpose_LIBRARY:                cdx.ComponentTypeLibrary,
		sbom.Purpose_MODULE:                 cdx.ComponentTypeLibrary,
		sbom.Purpose_MACHINE_LEARNING_MODEL: cdx.ComponentTypeMachineLearningModel,
		sbom.Purpose_MODEL:                  cdx.ComponentTypeMachineLearningModel,
		sbom.Purpose_OPERATING_SYSTEM:       cdx.ComponentTypeOS,
		sbom.Purpose_PLATFORM:               cdx.ComponentTypePlatform,
	} {
		res, err := cdxs.purposeToComponentType(protoPupose)
		require.NoError(t, err)
		require.Equal(t, cdxType, res)
	}
}

func TestNodeURLsToComponent(t *testing.T) {
	sut := NewCDX("1.5", "json")

	t.Run("urls become references", func(t *testing.T) {
		c := sut.nodeToComponent(&sbom.Node{
			Id:          "pkg",
			UrlHome:     "https://example.com/",
			UrlDownload: "git+https://example.com/repo@abc123",
		})
		require.Equal(t, []cdx.ExternalReference{
			{URL: "https://example.com/", Type: cdx.ERTypeWebsite},
			{URL: "git+https://example.com/repo@abc123", Type: cdx.ERTypeDistribution},
		}, *c.ExternalReferences)
	})

	t.Run("existing references are not duplicated", func(t *testing.T) {
		c := sut.nodeToComponent(&sbom.Node{
			Id:          "pkg",
			UrlDownload: "https://example.com/pkg.tgz",
			ExternalReferences: []*sbom.ExternalReference{
				{
					Url:     "https://example.com/pkg.tgz",
					Type:    sbom.ExternalReference_DOWNLOAD,
					Comment: "mirror",
				},
			},
		})
		require.Len(t, *c.ExternalReferences, 1)
		require.Equal(t, cdx.ERTypeDistribution, (*c.ExternalReferences)[0].Type)
		require.Equal(t, "mirror", (*c.ExternalReferences)[0].Comment)
	})

	t.Run("empty urls add nothing", func(t *testing.T) {
		c := sut.nodeToComponent(&sbom.Node{Id: "pkg"})
		require.Empty(t, *c.ExternalReferences)
	})
}

func TestDocumentTypeToLifecycle(t *testing.T) {
	for name, tc := range map[string]struct {
		dt       *sbom.DocumentType
		expected cdx.Lifecycle
	}{
		"build": {
			&sbom.DocumentType{Type: sbom.DocumentType_BUILD.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseBuild},
		},
		"design": {
			&sbom.DocumentType{Type: sbom.DocumentType_DESIGN.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseDesign},
		},
		"analyzed": {
			&sbom.DocumentType{Type: sbom.DocumentType_ANALYZED.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhasePostBuild},
		},
		"source": {
			&sbom.DocumentType{Type: sbom.DocumentType_SOURCE.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhasePreBuild},
		},
		"decommission": {
			&sbom.DocumentType{Type: sbom.DocumentType_DECOMISSION.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseDecommission},
		},
		"deployed": {
			&sbom.DocumentType{Type: sbom.DocumentType_DEPLOYED.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseOperations},
		},
		"discovery": {
			&sbom.DocumentType{Type: sbom.DocumentType_DISCOVERY.Enum()},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseDiscovery},
		},
		"phase drops name and description": {
			&sbom.DocumentType{
				Type: sbom.DocumentType_BUILD.Enum(), Name: ptr("CI build"), Description: ptr("built on CI"),
			},
			cdx.Lifecycle{Phase: cdx.LifecyclePhaseBuild},
		},
		// RUNTIME and OTHER have no CycloneDX phase, they are named lifecycles.
		"runtime without name": {
			&sbom.DocumentType{Type: sbom.DocumentType_RUNTIME.Enum()},
			cdx.Lifecycle{Name: "runtime"},
		},
		"runtime with name and description": {
			&sbom.DocumentType{
				Type: sbom.DocumentType_RUNTIME.Enum(), Name: ptr("Runtime capture"), Description: ptr("eBPF probe"),
			},
			cdx.Lifecycle{Name: "Runtime capture", Description: "eBPF probe"},
		},
		"other without name": {
			&sbom.DocumentType{Type: sbom.DocumentType_OTHER.Enum()},
			cdx.Lifecycle{Name: "other"},
		},
		"other with name": {
			&sbom.DocumentType{Type: sbom.DocumentType_OTHER.Enum(), Name: ptr("Audit"), Description: ptr("yearly")},
			cdx.Lifecycle{Name: "Audit", Description: "yearly"},
		},
		"no type": {
			&sbom.DocumentType{Name: ptr("custom"), Description: ptr("custom stage")},
			cdx.Lifecycle{Name: "custom", Description: "custom stage"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, documentTypeToLifecycle(tc.dt))
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestNodeConcludedLicenseToComponent(t *testing.T) {
	concluded := func(id string) cdx.LicenseChoice {
		return cdx.LicenseChoice{License: &cdx.License{ID: id, Acknowledgement: cdx.LicenseAcknowledgementConcluded}}
	}
	for name, tc := range map[string]struct {
		version   string
		declared  []string
		concluded string
		expected  cdx.Licenses
	}{
		"concluded equal to the single declared license is not written": {
			"1.6",
			[]string{"MIT"},
			"MIT",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
		},
		"concluded equal to the derived join is not written": {
			"1.6",
			[]string{"MIT", "Apache-2.0"},
			"MIT OR Apache-2.0",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, {License: &cdx.License{ID: "Apache-2.0"}}},
		},
		"concluded differing from declared is written": {
			"1.6",
			[]string{"MIT"},
			"Apache-2.0",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, concluded("Apache-2.0")},
		},
		"concluded alone is written": {
			"1.6", nil, "GPL-3.0-or-later",
			cdx.Licenses{concluded("GPL-3.0-or-later")},
		},
		"concluded expression is written on the choice": {
			"1.6",
			[]string{"BSD-3-Clause"},
			"MIT OR GPL-2.0-only",
			cdx.Licenses{
				{License: &cdx.License{ID: "BSD-3-Clause"}},
				{Expression: "MIT OR GPL-2.0-only", Acknowledgement: ptr(cdx.LicenseAcknowledgementConcluded)},
			},
		},
		"concluded is not written below 1.6": {
			"1.5",
			[]string{"MIT"},
			"Apache-2.0",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
		},
		"concluded reference minted from a name is written as an acknowledged name": {
			"1.6",
			[]string{"MIT"},
			"LicenseRef-x-protobom-GPL",
			cdx.Licenses{
				{License: &cdx.License{ID: "MIT"}},
				{License: &cdx.License{Name: "GPL", Acknowledgement: cdx.LicenseAcknowledgementConcluded}},
			},
		},
		"concluded reference from spdx is written as an acknowledged expression": {
			"1.6",
			[]string{"MIT"},
			"LicenseRef-GPL",
			cdx.Licenses{
				{License: &cdx.License{ID: "MIT"}},
				{Expression: "LicenseRef-GPL", Acknowledgement: ptr(cdx.LicenseAcknowledgementConcluded)},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			sut := NewCDX(tc.version, "json")
			comp := sut.nodeToComponent(&sbom.Node{Licenses: tc.declared, LicenseConcluded: tc.concluded})
			require.NotNil(t, comp.Licenses)
			require.Equal(t, tc.expected, *comp.Licenses)
		})
	}
}

// TestSerializeIsDeterministic pins the output order of everything the
// serializer reads from a map or a graph walk: hashes, identifiers, external
// reference hashes and the component tree. Writing the same document twice
// must give the same bytes, and the order must be the one documented.
func TestSerializeIsDeterministic(t *testing.T) {
	doc := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", Version: "1"},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{
					Id: "root", Name: "root",
					Hashes: map[int32]string{
						int32(sbom.HashAlgorithm_SHA512): "c",
						int32(sbom.HashAlgorithm_MD5):    "a",
						int32(sbom.HashAlgorithm_SHA256): "b",
					},
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_CPE22): "cpe:/a:v:p:1",
						int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*",
						int32(sbom.SoftwareIdentifierType_PURL):  "pkg:generic/p@1",
					},
					ExternalReferences: []*sbom.ExternalReference{{
						Url: "https://example.com/p.tgz", Type: sbom.ExternalReference_DOWNLOAD,
						Hashes: map[int32]string{
							int32(sbom.HashAlgorithm_SHA384): "y",
							int32(sbom.HashAlgorithm_SHA1):   "x",
						},
					}},
				},
				{Id: "c", Name: "c"},
				{Id: "a", Name: "a"},
				{Id: "b", Name: "b"},
				{Id: "b1", Name: "b1"},
				{Id: "b2", Name: "b2"},
			},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: "root", To: []string{"c", "a", "b"}},
				{Type: sbom.Edge_contains, From: "b", To: []string{"b2", "b1"}},
			},
			RootElements: []string{"root"},
		},
	}

	sut := NewCDX("1.6", "json")
	render := func() (*cdx.BOM, []byte) {
		out, err := sut.Serialize(doc, &native.SerializeOptions{}, nil)
		require.NoError(t, err)
		bom, ok := out.(*cdx.BOM)
		require.True(t, ok)
		var buf bytes.Buffer
		require.NoError(t, sut.Render(bom, &buf, nil, nil))
		return bom, buf.Bytes()
	}

	bom, first := render()
	for range 20 {
		_, again := render()
		require.Equal(t, string(first), string(again))
	}

	root := bom.Metadata.Component
	require.Equal(t, []cdx.Hash{
		{Algorithm: cdx.HashAlgoMD5, Value: "a"},
		{Algorithm: cdx.HashAlgoSHA256, Value: "b"},
		{Algorithm: cdx.HashAlgoSHA512, Value: "c"},
	}, *root.Hashes)
	require.Equal(t, "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", root.CPE, "CPE 2.3 wins over 2.2 whatever the order")
	require.Equal(t, []cdx.Hash{
		{Algorithm: cdx.HashAlgoSHA1, Value: "x"},
		{Algorithm: cdx.HashAlgoSHA384, Value: "y"},
	}, *(*root.ExternalReferences)[0].Hashes)

	// The component tree follows the order the containing edges state.
	names := func(comps *[]cdx.Component) []string {
		out := make([]string, 0, len(*comps))
		for _, c := range *comps {
			out = append(out, c.Name)
		}
		return out
	}
	require.Equal(t, []string{"c", "a", "b"}, names(bom.Components))
	require.Equal(t, []string{"b2", "b1"}, names((*bom.Components)[2].Components))
}

func TestNodeContentTypeToComponent(t *testing.T) {
	sut := CDX{}
	for name, tc := range map[string]struct {
		contentType string
		expected    string
	}{
		"media type":               {"application/json", "application/json"},
		"with suffix and plus":     {"application/vnd.cyclonedx+json", "application/vnd.cyclonedx+json"},
		"upper case is normalized": {"Application/JSON", "application/json"},
		"surrounding whitespace":   {" image/png ", "image/png"},
		"empty":                    {"", ""},
		"not a media type":         {"json", ""},
		"with parameters":          {"text/plain; charset=utf-8", ""},
		"too many parts":           {"a/b/c", ""},
	} {
		t.Run(name, func(t *testing.T) {
			comp := sut.nodeToComponent(&sbom.Node{ContentType: tc.contentType})
			require.Equal(t, tc.expected, comp.MIMEType)
		})
	}
}

// A security policy reference is written as the RFC 9116 type only when its
// URL points at a security.txt file, the one thing that type means.
func TestSecurityPolicyToComponent(t *testing.T) {
	sut := CDX{}
	for name, tc := range map[string]struct {
		url      string
		expected cdx.ExternalReferenceType
	}{
		"well known location":  {"https://example.com/.well-known/security.txt", cdx.ERTypeRFC9116},
		"legacy location":      {"https://example.com/security.txt", cdx.ERTypeRFC9116},
		"upper case file name": {"https://example.com/.well-known/SECURITY.TXT", cdx.ERTypeRFC9116},
		"with query":           {"https://example.com/.well-known/security.txt?v=2", cdx.ERTypeRFC9116},
		"policy page":          {"https://example.com/security", cdx.ERTypeOther},
		"markdown policy":      {"https://github.com/org/repo/blob/main/SECURITY.md", cdx.ERTypeOther},
		"file name elsewhere":  {"https://example.com/security.txt.bak", cdx.ERTypeOther},
		"not a url":            {"::not a url", cdx.ERTypeOther},
	} {
		t.Run(name, func(t *testing.T) {
			comp := sut.nodeToComponent(&sbom.Node{ExternalReferences: []*sbom.ExternalReference{
				{Url: tc.url, Type: sbom.ExternalReference_SECURITY_POLICY},
			}})
			require.Len(t, *comp.ExternalReferences, 1)
			require.Equal(t, tc.expected, (*comp.ExternalReferences)[0].Type)
		})
	}
}

func TestCDXDocumentVersion(t *testing.T) {
	for name, tc := range map[string]struct {
		version  string
		expected int
	}{
		"one":              {"1", 1},
		"revision":         {"7", 7},
		"with whitespace":  {" 3 ", 3},
		"empty is default": {"", 1},
		"zero":             {"0", 1},
		"negative":         {"-2", 1},
		"not an integer":   {"1.0", 1},
		"semantic version": {"v2", 1},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, cdxDocumentVersion(tc.version))
		})
	}
}
