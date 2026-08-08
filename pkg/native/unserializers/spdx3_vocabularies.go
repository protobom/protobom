// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/software"

	"github.com/protobom/protobom/pkg/sbom"
)

// The vocabularies SPDX 3 states as strings, read back into the enumerations
// protobom holds them in. Each is the reverse of the mapping the SPDX 3
// serializer writes with; where the two vocabularies are not the same size,
// the comments say what is lost.

// spdx3ExternalRefTypes reverses the serializer's external reference mapping.
// The two vocabularies agree on all but two names, which SPDX 3 spells
// differently: a download is an altDownloadLocation and a website an
// altWebPage.
var spdx3ExternalRefTypes = map[core.ExternalRefType]sbom.ExternalReference_ExternalReferenceType{
	core.ExternalRefTypeAltDownloadLocation:                   sbom.ExternalReference_DOWNLOAD,
	core.ExternalRefTypeAltWebPage:                            sbom.ExternalReference_WEBSITE,
	core.ExternalRefTypeBinaryArtifact:                        sbom.ExternalReference_BINARY,
	core.ExternalRefTypeBower:                                 sbom.ExternalReference_BOWER,
	core.ExternalRefTypeBuildMeta:                             sbom.ExternalReference_BUILD_META,
	core.ExternalRefTypeBuildSystem:                           sbom.ExternalReference_BUILD_SYSTEM,
	core.ExternalRefTypeCertificationReport:                   sbom.ExternalReference_CERTIFICATION_REPORT,
	core.ExternalRefTypeChat:                                  sbom.ExternalReference_CHAT,
	core.ExternalRefTypeComponentAnalysisReport:               sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT,
	core.ExternalRefTypeDocumentation:                         sbom.ExternalReference_DOCUMENTATION,
	core.ExternalRefTypeDynamicAnalysisReport:                 sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT,
	core.ExternalRefTypeEolNotice:                             sbom.ExternalReference_EOL_NOTICE,
	core.ExternalRefTypeExportControlAssessment:               sbom.ExternalReference_EXPORT_CONTROL_ASSESSMENT,
	core.ExternalRefTypeFunding:                               sbom.ExternalReference_FUNDING,
	core.ExternalRefTypeIssueTracker:                          sbom.ExternalReference_ISSUE_TRACKER,
	core.ExternalRefTypeLicense:                               sbom.ExternalReference_LICENSE,
	core.ExternalRefTypeMailingList:                           sbom.ExternalReference_MAILING_LIST,
	core.ExternalRefTypeMavenCentral:                          sbom.ExternalReference_MAVEN_CENTRAL,
	core.ExternalRefTypeMetrics:                               sbom.ExternalReference_METRICS,
	core.ExternalRefTypeNpm:                                   sbom.ExternalReference_NPM,
	core.ExternalRefTypeNuget:                                 sbom.ExternalReference_NUGET,
	core.ExternalRefTypeOther:                                 sbom.ExternalReference_OTHER,
	core.ExternalRefTypePrivacyAssessment:                     sbom.ExternalReference_PRIVACY_ASSESSMENT,
	core.ExternalRefTypeProductMetadata:                       sbom.ExternalReference_PRODUCT_METADATA,
	core.ExternalRefTypePurchaseOrder:                         sbom.ExternalReference_PURCHASE_ORDER,
	core.ExternalRefTypeQualityAssessmentReport:               sbom.ExternalReference_QUALITY_ASSESSMENT_REPORT,
	core.ExternalRefTypeReleaseHistory:                        sbom.ExternalReference_RELEASE_HISTORY,
	core.ExternalRefTypeReleaseNotes:                          sbom.ExternalReference_RELEASE_NOTES,
	core.ExternalRefTypeRiskAssessment:                        sbom.ExternalReference_RISK_ASSESSMENT,
	core.ExternalRefTypeRuntimeAnalysisReport:                 sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT,
	core.ExternalRefTypeSecureSoftwareAttestation:             sbom.ExternalReference_SECURE_SOFTWARE_ATTESTATION,
	core.ExternalRefTypeSecurityAdversaryModel:                sbom.ExternalReference_SECURITY_ADVERSARY_MODEL,
	core.ExternalRefTypeSecurityAdvisory:                      sbom.ExternalReference_SECURITY_ADVISORY,
	core.ExternalRefTypeSecurityFix:                           sbom.ExternalReference_SECURITY_FIX,
	core.ExternalRefTypeSecurityOther:                         sbom.ExternalReference_SECURITY_OTHER,
	core.ExternalRefTypeSecurityPenTestReport:                 sbom.ExternalReference_SECURITY_PENTEST_REPORT,
	core.ExternalRefTypeSecurityPolicy:                        sbom.ExternalReference_SECURITY_POLICY,
	core.ExternalRefTypeSecurityThreatModel:                   sbom.ExternalReference_SECURITY_THREAT_MODEL,
	core.ExternalRefTypeSocialMedia:                           sbom.ExternalReference_SOCIAL,
	core.ExternalRefTypeSourceArtifact:                        sbom.ExternalReference_SOURCE_ARTIFACT,
	core.ExternalRefTypeStaticAnalysisReport:                  sbom.ExternalReference_STATIC_ANALYSIS_REPORT,
	core.ExternalRefTypeSupport:                               sbom.ExternalReference_SUPPORT,
	core.ExternalRefTypeVcs:                                   sbom.ExternalReference_VCS,
	core.ExternalRefTypeVulnerabilityDisclosureReport:         sbom.ExternalReference_VULNERABILITY_DISCLOSURE_REPORT,
	core.ExternalRefTypeVulnerabilityExploitabilityAssessment: sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT,
}

// externalRefTypeFromSPDX3 returns the protobom reference type an SPDX 3 one
// names. An unknown type is read as OTHER rather than dropped: the reference
// still has a URL worth keeping.
func externalRefTypeFromSPDX3(t core.ExternalRefType) sbom.ExternalReference_ExternalReferenceType {
	if known, ok := spdx3ExternalRefTypes[t]; ok {
		return known
	}
	return sbom.ExternalReference_OTHER
}

// identifierTypeFromSPDX3 returns the protobom identifier type an SPDX 3
// external identifier names.
//
// TODO(degradation): SPDX 3 has eleven identifier types and protobom four,
// so a cpe22 in an email or a swid has nowhere to go.
func identifierTypeFromSPDX3(t core.ExternalIdentifierType) sbom.SoftwareIdentifierType {
	switch t {
	case core.ExternalIdentifierTypePackageUrl:
		return sbom.SoftwareIdentifierType_PURL
	case core.ExternalIdentifierTypeCpe22:
		return sbom.SoftwareIdentifierType_CPE22
	case core.ExternalIdentifierTypeCpe23:
		return sbom.SoftwareIdentifierType_CPE23
	case core.ExternalIdentifierTypeGitoid:
		return sbom.SoftwareIdentifierType_GITOID
	default:
		return sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE
	}
}

// fileKindFromSPDX3 says whether an element is a file or a directory, which
// is all SPDX 3's fileKind distinguishes.
func fileKindFromSPDX3(k software.FileKindType) sbom.Node_FileKind {
	switch k {
	case software.FileKindTypeFile:
		return sbom.Node_FILE_KIND_FILE
	case software.FileKindTypeDirectory:
		return sbom.Node_FILE_KIND_DIRECTORY
	default:
		return sbom.Node_UNKNOWN_FILE_KIND
	}
}

// spdx3Purposes reverses the serializer's purpose mapping. It is not an exact
// inverse, because the forward mapping is not injective: protobom's device
// driver and platform are written as SPDX 3's device and other, and both of
// its model purposes as model. Read back, each SPDX 3 purpose becomes the
// protobom purpose that names the same thing.
var spdx3Purposes = map[software.SoftwarePurpose]sbom.Purpose{
	software.SoftwarePurposeApplication:     sbom.Purpose_APPLICATION,
	software.SoftwarePurposeArchive:         sbom.Purpose_ARCHIVE,
	software.SoftwarePurposeBom:             sbom.Purpose_BOM,
	software.SoftwarePurposeConfiguration:   sbom.Purpose_CONFIGURATION,
	software.SoftwarePurposeContainer:       sbom.Purpose_CONTAINER,
	software.SoftwarePurposeData:            sbom.Purpose_DATA,
	software.SoftwarePurposeDevice:          sbom.Purpose_DEVICE,
	software.SoftwarePurposeDeviceDriver:    sbom.Purpose_DEVICE_DRIVER,
	software.SoftwarePurposeDocumentation:   sbom.Purpose_DOCUMENTATION,
	software.SoftwarePurposeEvidence:        sbom.Purpose_EVIDENCE,
	software.SoftwarePurposeExecutable:      sbom.Purpose_EXECUTABLE,
	software.SoftwarePurposeFile:            sbom.Purpose_FILE,
	software.SoftwarePurposeFirmware:        sbom.Purpose_FIRMWARE,
	software.SoftwarePurposeFramework:       sbom.Purpose_FRAMEWORK,
	software.SoftwarePurposeInstall:         sbom.Purpose_INSTALL,
	software.SoftwarePurposeLibrary:         sbom.Purpose_LIBRARY,
	software.SoftwarePurposeManifest:        sbom.Purpose_MANIFEST,
	software.SoftwarePurposeModel:           sbom.Purpose_MODEL,
	software.SoftwarePurposeModule:          sbom.Purpose_MODULE,
	software.SoftwarePurposeOperatingSystem: sbom.Purpose_OPERATING_SYSTEM,
	software.SoftwarePurposeOther:           sbom.Purpose_OTHER,
	software.SoftwarePurposePatch:           sbom.Purpose_PATCH,
	software.SoftwarePurposePlatform:        sbom.Purpose_PLATFORM,
	software.SoftwarePurposeRequirement:     sbom.Purpose_REQUIREMENT,
	software.SoftwarePurposeSource:          sbom.Purpose_SOURCE,
	software.SoftwarePurposeSpecification:   sbom.Purpose_SPECIFICATION,
	software.SoftwarePurposeTest:            sbom.Purpose_TEST,

	// TODO(degradation): protobom has no purpose for a disk image or a
	// filesystem image, so those two are dropped.
}

// purposesFromSPDX3 joins the purpose SPDX 3 calls primary and those it calls
// additional back into the single list protobom holds, primary first.
func purposesFromSPDX3(primary software.SoftwarePurpose, additional []software.SoftwarePurpose) []sbom.Purpose {
	purposes := []sbom.Purpose{}
	for _, p := range append([]software.SoftwarePurpose{primary}, additional...) {
		if known, ok := spdx3Purposes[p]; ok {
			purposes = append(purposes, known)
		}
	}
	return purposes
}
