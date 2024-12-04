package unserializers

import (
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	cdxformats "github.com/protobom/protobom/pkg/formats/cyclonedx"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Unserializer = &CDX{}

type CDX struct {
	version  string
	encoding string
}

func NewCDX(version, encoding string) *CDX {
	return &CDX{
		version:  version,
		encoding: encoding,
	}
}

// Unserialize reads datq data from io.Reader r and parses it as a CycloneDX
// document. If successful returns a protobom Document loaded with the SBOM data.
func (u *CDX) Unserialize(r io.Reader, _ *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	bom := new(cdx.BOM)

	encoding, err := cdxformats.ParseEncoding(u.encoding)
	if err != nil {
		return nil, err
	}
	decoder := cdx.NewBOMDecoder(r, encoding)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding cyclonedx: %w", err)
	}

	md := &sbom.Metadata{
		Id:      bom.SerialNumber,
		Version: fmt.Sprintf("%d", bom.Version),
		Date:    &timestamppb.Timestamp{},
		Tools:   []*sbom.Tool{},
		Authors: []*sbom.Person{},
	}

	doc := &sbom.Document{
		Metadata: md,
		NodeList: &sbom.NodeList{},
	}

	cc := 0

	if bom.Metadata != nil {
		if bom.Metadata.Lifecycles != nil {
			for _, lc := range *bom.Metadata.Lifecycles {
				lc := lc
				name := lc.Name
				desc := lc.Description
				t := u.phaseToSBOMType(&lc.Phase)
				if name == "" {
					name = string(lc.Phase)
				}

				md.DocumentTypes = append(md.DocumentTypes, &sbom.DocumentType{
					Name:        &name,
					Description: &desc,
					Type:        t,
				})
			}
		}
		if bom.Metadata.Component != nil {
			nl, err := u.componentToNodeList(bom.Metadata.Component, &cc)
			if err != nil {
				return nil, fmt.Errorf("converting main bom component to node: %w", err)
			}
			if len(nl.RootElements) > 1 {
				logrus.Warnf("root nodelist has %d components, this should not happen", len(nl.RootElements))
			}
			doc.NodeList.Add(nl)
		}
	}

	// Cycle all components and get their graph fragments
	if bom.Components != nil {
		for i := range *bom.Components {
			nl, err := u.componentToNodeList(&(*bom.Components)[i], &cc)
			if err != nil {
				return nil, fmt.Errorf("converting component to node: %w", err)
			}

			if len(doc.NodeList.RootElements) == 0 {
				doc.NodeList.Add(nl)
			} else {
				if err := doc.NodeList.RelateNodeListAtID(nl, doc.NodeList.RootElements[0], sbom.Edge_contains); err != nil {
					return nil, fmt.Errorf("relating components to root node: %w", err)
				}
			}
		}
	}

	return doc, nil
}

// componentToNodes takes a CycloneDX component and computes its graph fragment,
// returning a nodelist
func (u *CDX) componentToNodeList(component *cdx.Component, cc *int) (*sbom.NodeList, error) {
	node, err := u.componentToNode(component, cc)
	if err != nil {
		return nil, fmt.Errorf("converting cdx component to node: %w", err)
	}

	nl := &sbom.NodeList{
		Nodes:        []*sbom.Node{node},
		Edges:        []*sbom.Edge{},
		RootElements: []string{node.Id},
	}

	if component.Components != nil {
		for i := range *component.Components {
			subList, err := u.componentToNodeList(&(*component.Components)[i], cc)
			if err != nil {
				return nil, fmt.Errorf("converting subcomponent to nodelist: %w", err)
			}
			if err := nl.RelateNodeListAtID(subList, node.Id, sbom.Edge_contains); err != nil {
				return nil, fmt.Errorf("relating subcomponents to new node: %w", err)
			}
		}
	}

	return nl, nil
}

func (u *CDX) componentToNode(c *cdx.Component, cc *int) (*sbom.Node, error) { //nolint:unparam
	(*cc)++
	node := &sbom.Node{
		Id:      c.BOMRef,
		Type:    sbom.Node_PACKAGE,
		Name:    c.Name,
		Version: c.Version,
		// UrlHome:     "", // Perhaps it would make sense to use the supplier URL here
		UrlDownload:        "",
		Licenses:           u.licenseChoicesToLicenseList(c.Licenses),
		LicenseConcluded:   u.licenseChoicesToLicenseString(c.Licenses),
		Copyright:          c.Copyright,
		Hashes:             map[int32]string{},
		Description:        c.Description,
		Attribution:        []string{},
		Suppliers:          []*sbom.Person{}, // TODO
		Originators:        []*sbom.Person{}, // TODO
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        map[int32]string{},
		FileTypes:          []string{},
	}

	node.PrimaryPurpose = []sbom.Purpose{u.componentTypeToPurpose(c.Type)}

	// Protobom recognizes files in CycloneDX SBOMs when a component is of
	// type file. In that case we flip the type bit:
	if u.componentTypeToPurpose(c.Type) == sbom.Purpose_FILE {
		node.Type = sbom.Node_FILE
	}

	node.ExternalReferences = u.unserializeExternalReferences(c.ExternalReferences)

	// Named external references:
	if c.CPE != "" {
		t := sbom.SoftwareIdentifierType_CPE22
		if strings.HasPrefix(c.CPE, "cpe:2.3") {
			t = sbom.SoftwareIdentifierType_CPE23
		}
		node.Identifiers[int32(t)] = c.CPE
	}

	if c.PackageURL != "" {
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = c.PackageURL
	}

	if c.Hashes != nil {
		for _, h := range *c.Hashes {
			algo := sbom.HashAlgorithmFromCDX(h.Algorithm)
			if algo == sbom.HashAlgorithm_UNKNOWN {
				// TODO(degradation): Well, not deprecation but invalid SBOM
				continue
			}

			if _, ok := node.Hashes[int32(algo)]; ok {
				// TODO(degradation): Data loss from two hashes of the same algorithm
				continue
			}
			node.Hashes[int32(algo)] = h.Value
		}
	}

	if c.Properties != nil && len(*c.Properties) > 0 {
		ps := []*sbom.Property{}
		for _, p := range *c.Properties {
			protoprop := sbom.NewProperty()
			protoprop.Name = p.Name
			protoprop.Data = p.Value
			ps = append(ps, protoprop)
		}
		node.Properties = ps
	}

	// Generate a new ID if none is set
	if node.Id == "" {
		node.Id = sbom.NewNodeIdentifier("auto", fmt.Sprintf("%09d", *cc))
	}

	return node, nil
}

// unserializeExternalReferences reads a slice of cyclonedx references and returns
// tjeir protobom equivalents.
func (u *CDX) unserializeExternalReferences(cdxReferences *[]cdx.ExternalReference) []*sbom.ExternalReference {
	ret := []*sbom.ExternalReference{}
	// If there are no ext references. Done.
	if cdxReferences == nil {
		return ret
	}

	for _, extRef := range *cdxReferences {
		nref := &sbom.ExternalReference{
			Url:     extRef.URL,
			Comment: extRef.Comment,
			Hashes:  map[int32]string{},
			Type:    u.cdxExtRefTypeToProtobomType(extRef.Type),
		}
		if extRef.Hashes != nil {
			for _, h := range *extRef.Hashes {
				algo := int32(u.cdxHashAlgoToProtobomAlgo(h.Algorithm))
				// TODO(degradation): Data loss happens if algorithm is repeated
				// TODO(degradation): Data loss most likely when reading unknown algorithms
				nref.Hashes[algo] = h.Value
			}
		}
		ret = append(ret, nref)
	}
	return ret
}

// licenseChoicesToLicenseList returns a flat list of license strings combining
// expressions and IDs in one. This function should be part of a license package.
func (u *CDX) licenseChoicesToLicenseList(lcs *cdx.Licenses) []string {
	list := []string{}
	if lcs == nil {
		return list
	}
	for _, lc := range *lcs {
		// TODO(license): This should handle licenses without an ID and
		// create custom licenses or another solution that captures the
		// full cuistom license text.
		if lc.Expression == "" && lc.License.ID == "" {
			continue
		}

		if lc.Expression != "" {
			list = append(list, lc.Expression)
		} else {
			list = append(list, lc.License.ID)
		}
		return list
	}

	return list
}

// licenseChoicesToLicenseString takes the component license data and computes
// a license expression with its license entries. It will return the license or
// expression verbatim if its just a single entry.
// This function is temporary and probably should be part of a more complete
// license package.
func (u *CDX) licenseChoicesToLicenseString(lcs *cdx.Licenses) string {
	if lcs == nil {
		return ""
	}
	s := ""
	for _, lc := range *lcs {
		// TODO(license): This should handle licenses without an ID and
		// create custom licenses or another solution that captures the
		// full cuistom license text.
		if lc.Expression == "" && lc.License.ID == "" {
			continue
		}
		if s != "" {
			s += fmt.Sprintf("(%s) OR ", s)
		}

		newLicense := ""
		if lc.Expression != "" {
			newLicense = lc.Expression
		} else {
			newLicense = lc.License.ID
		}
		if s == "" {
			s = newLicense
		} else {
			s += fmt.Sprintf(" (%s)", newLicense)
		}
	}
	return s
}

// phaseToSBOMType converts a CycloneDX lifecycle phase to an SBOM document type
// note that most of the CycloneDX phases are not mapped to SBOM document types and they would be used as OTHER
// this is a temporary solution until we have a better mapping
// see: https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf
func (u *CDX) phaseToSBOMType(ph *cdx.LifecyclePhase) *sbom.DocumentType_SBOMType {
	phase := *ph
	switch phase {
	case cdx.LifecyclePhaseBuild:
		return sbom.DocumentType_BUILD.Enum()
	case cdx.LifecyclePhaseDecommission:
		return sbom.DocumentType_DECOMISSION.Enum()
	case cdx.LifecyclePhaseDesign:
		return sbom.DocumentType_DESIGN.Enum()
	case cdx.LifecyclePhaseDiscovery:
		return sbom.DocumentType_DISCOVERY.Enum()
	case cdx.LifecyclePhaseOperations:
		return sbom.DocumentType_DEPLOYED.Enum()
	case cdx.LifecyclePhasePreBuild:
		return sbom.DocumentType_SOURCE.Enum()
	case cdx.LifecyclePhasePostBuild:
		return sbom.DocumentType_ANALYZED.Enum()
	default:
		return nil
	}
}

// componentTypeToPurpose converts the protobom catalog of purposes to the cyclonedx
// component type.
func (u *CDX) componentTypeToPurpose(cType cdx.ComponentType) sbom.Purpose {
	// CycloneDX 1.5 types: "application", "framework", "library", "container",
	// "platform", "operating-system", "device", "device-driver", "firmware",
	// "file", "machine-learning-model", "data"
	switch cType {
	case cdx.ComponentTypeApplication:
		return sbom.Purpose_APPLICATION
	case cdx.ComponentTypeFramework:
		return sbom.Purpose_FRAMEWORK
	case cdx.ComponentTypeLibrary:
		return sbom.Purpose_LIBRARY
	case cdx.ComponentTypeContainer:
		return sbom.Purpose_CONTAINER
	case cdx.ComponentTypePlatform:
		return sbom.Purpose_PLATFORM
	case cdx.ComponentTypeOS:
		return sbom.Purpose_OPERATING_SYSTEM
	case cdx.ComponentTypeDevice:
		return sbom.Purpose_DEVICE
	case cdx.ComponentTypeDeviceDriver:
		return sbom.Purpose_DEVICE_DRIVER
	case cdx.ComponentTypeFirmware:
		return sbom.Purpose_FIRMWARE
	case cdx.ComponentTypeFile:
		return sbom.Purpose_FILE
	case cdx.ComponentTypeMachineLearningModel:
		return sbom.Purpose_MACHINE_LEARNING_MODEL
	case cdx.ComponentTypeData:
		return sbom.Purpose_DATA
	default:
		return sbom.Purpose_UNKNOWN_PURPOSE
	}
}

// cdxHashAlgoToProtobomAlgo returns a protobom algorithm constant from a
// cyclonedx algorithm string
func (u *CDX) cdxHashAlgoToProtobomAlgo(cdxAlgo cdx.HashAlgorithm) sbom.HashAlgorithm {
	switch cdxAlgo {
	case cdx.HashAlgoMD5:
		return sbom.HashAlgorithm_MD5
	case cdx.HashAlgoSHA1:
		return sbom.HashAlgorithm_SHA1
	case cdx.HashAlgoSHA256:
		return sbom.HashAlgorithm_SHA256
	case cdx.HashAlgoSHA384:
		return sbom.HashAlgorithm_SHA384
	case cdx.HashAlgoSHA512:
		return sbom.HashAlgorithm_SHA512
	case cdx.HashAlgoSHA3_256:
		return sbom.HashAlgorithm_SHA3_256
	case cdx.HashAlgoSHA3_384:
		return sbom.HashAlgorithm_SHA3_384
	case cdx.HashAlgoSHA3_512:
		return sbom.HashAlgorithm_SHA3_512
	case cdx.HashAlgoBlake2b_256:
		return sbom.HashAlgorithm_BLAKE2B_256
	case cdx.HashAlgoBlake2b_384:
		return sbom.HashAlgorithm_BLAKE2B_384
	case cdx.HashAlgoBlake2b_512:
		return sbom.HashAlgorithm_BLAKE2B_512
	case cdx.HashAlgoBlake3:
		return sbom.HashAlgorithm_BLAKE3
	default:
		return sbom.HashAlgorithm_UNKNOWN
	}
}

// cdxExtRefTypeToProtobomType converts the cyclonedx references to our protobom
// enumarated values.
//
// Some values are missing in the CDX library that's why I'm creating them here.
// (I opened https://github.com/CycloneDX/cyclonedx-go/pull/129 to fix it)
func (u *CDX) cdxExtRefTypeToProtobomType(cdxExtRefType cdx.ExternalReferenceType) sbom.ExternalReference_ExternalReferenceType {
	switch cdxExtRefType {
	case cdx.ERTypeAttestation:
		return sbom.ExternalReference_ATTESTATION
	case cdx.ERTypeBOM:
		return sbom.ExternalReference_BOM
	case cdx.ERTypeBuildMeta:
		return sbom.ExternalReference_BUILD_META
	case cdx.ERTypeBuildSystem:
		return sbom.ExternalReference_BUILD_SYSTEM
	case cdx.ERTypeCertificationReport:
		return sbom.ExternalReference_CERTIFICATION_REPORT
	case cdx.ERTypeChat:
		return sbom.ExternalReference_CHAT
	case cdx.ERTypeCodifiedInfrastructure:
		return sbom.ExternalReference_CODIFIED_INFRASTRUCTURE
	case cdx.ERTypeComponentAnalysisReport:
		return sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT
	case cdx.ExternalReferenceType("configuration"):
		return sbom.ExternalReference_CONFIGURATION
	case cdx.ERTypeDistributionIntake:
		return sbom.ExternalReference_DISTRIBUTION_INTAKE
	case cdx.ERTypeDistribution:
		return sbom.ExternalReference_DOWNLOAD
	case cdx.ERTypeDocumentation:
		return sbom.ExternalReference_DOCUMENTATION
	case cdx.ERTypeDynamicAnalysisReport:
		return sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT
	case cdx.ExternalReferenceType("evidence"):
		return sbom.ExternalReference_EVIDENCE
	case cdx.ExternalReferenceType("formulation"):
		return sbom.ExternalReference_FORMULATION
	case cdx.ERTypeIssueTracker:
		return sbom.ExternalReference_ISSUE_TRACKER
	case cdx.ERTypeLicense:
		return sbom.ExternalReference_LICENSE
	case cdx.ExternalReferenceType("log"):
		return sbom.ExternalReference_LOG
	case cdx.ERTypeMailingList:
		return sbom.ExternalReference_MAILING_LIST
	case cdx.ERTypeMaturityReport:
		return sbom.ExternalReference_MATURITY_REPORT
	case cdx.ExternalReferenceType("model-card"):
		return sbom.ExternalReference_MODEL_CARD
	case cdx.ERTypeOther:
		return sbom.ExternalReference_OTHER
	case cdx.ExternalReferenceType("poam"):
		return sbom.ExternalReference_POAM
	case cdx.ERTypeQualityMetrics:
		return sbom.ExternalReference_QUALITY_METRICS
	case cdx.ERTypeReleaseNotes:
		return sbom.ExternalReference_RELEASE_NOTES
	case cdx.ERTypeRiskAssessment:
		return sbom.ExternalReference_RISK_ASSESSMENT
	case cdx.ERTypeRuntimeAnalysisReport:
		return sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT
	case cdx.ERTypeAdversaryModel:
		return sbom.ExternalReference_SECURITY_ADVERSARY_MODEL
	case cdx.ERTypeAdvisories:
		return sbom.ExternalReference_SECURITY_ADVISORY
	case cdx.ERTypeSecurityContact:
		return sbom.ExternalReference_SECURITY_CONTACT
	case cdx.ERTypePentestReport:
		return sbom.ExternalReference_SECURITY_PENTEST_REPORT
	case cdx.ERTypeThreatModel:
		return sbom.ExternalReference_SECURITY_THREAT_MODEL
	case cdx.ERTypeSocial:
		return sbom.ExternalReference_SOCIAL
	case cdx.ERTypeStaticAnalysisReport:
		return sbom.ExternalReference_STATIC_ANALYSIS_REPORT
	case cdx.ERTypeSupport:
		return sbom.ExternalReference_SUPPORT
	case cdx.ERTypeVCS:
		return sbom.ExternalReference_VCS
	case cdx.ERTypeVulnerabilityAssertion:
		return sbom.ExternalReference_VULNERABILITY_ASSERTION
	case cdx.ERTypeExploitabilityStatement:
		return sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT
	case cdx.ERTypeWebsite:
		return sbom.ExternalReference_WEBSITE
	default:
		return sbom.ExternalReference_OTHER
	}
}
