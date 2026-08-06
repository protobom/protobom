package serializers

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

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
