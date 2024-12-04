package beta

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

var _ native.Serializer = &SPDX3{}

type SPDX3Options struct {
	Indent int
}

func init() {
	writer.RegisterSerializer(formats.Format("text/spdx+json;version=3.0"), &SPDX3{})
}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

//nolint:unused // Document will be used when supporting JSON-LD framed mode
type document struct {
	Context string        `json:"@context"`
	Graph   []interface{} `json:"@graph"`
}

//nolint:unused // SPDX Document will be used when supporting JSON-LD framed mode
type spdxDocument struct {
	Type         string   `json:"type"` // SpdxDocument
	CreationInfo string   `json:"creationInfo,omitempty"`
	Name         string   `json:"name"`
	Elements     []string `json:"element"`
	RootElements []string `json:"rootElement"`
}

type sbomType struct {
	Type         string        `json:"type"` // Sbom
	CreationInfo *creationInfo `json:"creationInfo,omitempty"`
	SbomType     string        `json:"sbomType,omitempty"`
	Elements     []interface{} `json:"element"` // o strings?
	RootElements []string      `json:"rootElement"`
}

type creationInfo struct {
	ID          string     `json:"@id,omitempty"`
	Type        string     `json:"type"` // SpdxDocument
	SpecVersion string     `json:"specVersion"`
	Created     *time.Time `json:"created"`
	CreatedBy   []string   `json:"createdBy,omitempty"`
	Profiles    []string   `json:"profile,omitempty"`
	DataLicense string     `json:"dataLicense"`
}

type file struct {
	Type              string        `json:"type"` // File
	SpdxId            string        `json:"SpdxId,omitempty"`
	Name              string        `json:"name"`
	ContentType       string        `json:"contentType,omitempty"` // "image/png"
	Purpose           []string      `json:"purpose,omitempty"`
	ContentIdentifier string        `json:"contentIdentifier,omitempty"`
	CreationInfo      *creationInfo `json:"creationInfo,omitempty"`
}
type relationship struct {
	Type             string        `json:"type"` // Relationship
	SpdxId           string        `json:"SpdxId,omitempty"`
	From             string        `json:"from"`
	To               []string      `json:"to"`
	RelationshipType string        `json:"relationshipType"`
	CreationInfo     *creationInfo `json:"creationInfo,omitempty"`
}

type pkg struct {
	ID                 string              `json:"@id,omitempty"`
	Type               string              `json:"type"` // Package
	SpdxId             string              `json:"SpdxId,omitempty"`
	CreationInfo       *creationInfo       `json:"creationInfo,omitempty"`
	Name               string              `json:"name"`
	Summary            string              `json:"summary,omitempty"`
	Description        string              `json:"description,omitempty"`
	Comment            string              `json:"comment,omitempty"`
	Version            string              `json:"packageVersion,omitempty"`
	DownloadLocation   string              `json:"downloadLocation,omitempty"`
	PackageUrl         string              `json:"packageUrl,omitempty"`
	HomePage           string              `json:"homepage,omitempty"`
	Purpose            []string            `json:"purpose,omitempty"`
	ContentIdentifier  string              `json:"contentIdentifier,omitempty"`
	OriginatedBy       []string            `json:"originatedBy,omitempty"`
	SuppliedBy         []string            `json:"suppliedBy,omitempty"`
	VerifiedUsing      []hashList          `json:"verifiedUsing,omitempty"`
	ExternalReferences []externalReference `json:"externalReference,omitempty"`
}

type externalReference struct {
	Type                  string // ExternalReference
	ExternalReferenceType string `json:"externalReferenceType"`
	Locator               []string
}

type hashList struct {
	Type      string // "Hash",
	Algorithm string
	HashValue string `json:"hashValue"`
}

type SPDX3 struct{}

func (spdx3 *SPDX3) Serialize(bom *sbom.Document, _ *native.SerializeOptions, _ interface{}) (interface{}, error) {
	now := time.Now()
	spdxSBOM := sbomType{
		Type: "Sbom",
		CreationInfo: &creationInfo{
			Type:        "CreationInfo",
			SpecVersion: "3.0.0",
			Created:     &now,
			CreatedBy:   []string{},
			Profiles:    []string{},
			DataLicense: "https://spdx.org/licenses/CC0-1.0",
		},
		SbomType:     "",
		Elements:     []interface{}{},
		RootElements: []string{},
	}

	// Transfer the ids of the root nodes verbatim
	spdxSBOM.RootElements = bom.NodeList.RootElements

	// Cycle nodes and add them to the elements array
	for _, n := range bom.NodeList.Nodes {
		switch n.Type {
		case sbom.Node_PACKAGE:
			p, err := spdx3.nodeToPackage(n)
			if err != nil {
				return nil, fmt.Errorf("creating package from node: %w", err)
			}
			spdxSBOM.Elements = append(spdxSBOM.Elements, p)
		case sbom.Node_FILE:
			f, err := spdx3.nodeToFile(n)
			if err != nil {
				return nil, fmt.Errorf("converting node to SPDX3 file: %w", err)
			}
			spdxSBOM.Elements = append(spdxSBOM.Elements, f)
		}
	}

	for _, e := range bom.NodeList.Edges {
		r, err := spdx3.edgeToRelationship(e)
		if err != nil {
			return nil, fmt.Errorf("converting edge to SPDX3 relationship: %w", err)
		}
		spdxSBOM.Elements = append(spdxSBOM.Elements, r)
	}

	return spdxSBOM, nil
}

// edgeToRelationship converts a protobom edge to an SPDX3 relationship
func (spdx3 *SPDX3) edgeToRelationship(e *sbom.Edge) (relationship, error) {
	if e.Type.String() == "" {
		return relationship{}, errors.New("unable to serialize relationship without type")
	}
	r := relationship{
		Type:             "Relationship",
		From:             e.From,
		To:               e.To,
		RelationshipType: e.Type.String(),
	}
	return r, nil
}

func (spdx3 *SPDX3) nodeToPackage(n *sbom.Node) (pkg, error) {
	if n.Type != sbom.Node_PACKAGE {
		return pkg{}, fmt.Errorf("attempt to serialize SPDX package from non pkg node")
	}
	p := pkg{
		ID:                 "",
		Type:               "Package",
		SpdxId:             n.Id,
		Name:               n.Name,
		Summary:            n.Summary,
		Description:        n.Description,
		Comment:            n.Comment,
		Version:            n.Version,
		DownloadLocation:   n.UrlDownload,
		PackageUrl:         string(n.Purl()),
		HomePage:           n.UrlHome,
		Purpose:            purposeStringsFromPurpose(n.PrimaryPurpose),
		ContentIdentifier:  "",
		OriginatedBy:       []string{},
		SuppliedBy:         []string{},
		VerifiedUsing:      []hashList{},
		ExternalReferences: []externalReference{},
	}

	for algo, h := range n.Hashes {
		ha := sbom.HashAlgorithm(algo)
		if ha.ToSPDX3() == "" {
			// TODO(degradation): Algoruithm not supperted in SPDX3
			continue
		}
		p.VerifiedUsing = append(p.VerifiedUsing, hashList{
			Type:      "Hash",
			Algorithm: ha.ToSPDX3(),
			HashValue: h,
		})
	}

	for _, ei := range n.ExternalReferences {
		p.ExternalReferences = append(p.ExternalReferences, externalReference{
			Type:                  "ExternalReference",
			ExternalReferenceType: spdx3.extRefTypeFromProtobomExtRef(ei),
			Locator:               []string{ei.Url},
		})
	}

	return p, nil
}

func (spdx3 *SPDX3) nodeToFile(n *sbom.Node) (file, error) {
	if n.Type != sbom.Node_FILE {
		return file{}, errors.New("attempt to build a file from a package node")
	}
	f := file{
		Type:              "File",
		SpdxId:            n.Id,
		Name:              n.Name,
		ContentType:       "",
		Purpose:           purposeStringsFromPurpose(n.PrimaryPurpose),
		ContentIdentifier: "",
	}
	return f, nil
}

func (spdx3 *SPDX3) Render(rawDoc interface{}, w io.Writer, o *native.RenderOptions, _ interface{}) error {
	doc, ok := rawDoc.(sbomType)
	if !ok {
		return errors.New("unable to cast SBOM as an SPDX 3.0 SBOM")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", strings.Repeat(" ", o.Indent))
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SBOM: %w", err)
	}
	return nil
}

func purposeStringsFromPurpose(purposes []sbom.Purpose) []string {
	var returnstrings []string

	for _, purpose := range purposes {
		// Allowed values: application, archive, bom, configuration, container, data, device, documentation, evidence, executable, file, firmware, framework, install, library, manifest, model, module, operatingSystem, other, patch, requirement, source, specification, test
		// Only two CDX values dont map perfectly:
		//  "device-driver" mapped to "device"
		//  "platform" mapped to "other"

		switch purpose {
		case sbom.Purpose_APPLICATION:
			returnstrings = append(returnstrings, "application")
		case sbom.Purpose_ARCHIVE:
			returnstrings = append(returnstrings, "archive")
		case sbom.Purpose_BOM:
			returnstrings = append(returnstrings, "bom")
		case sbom.Purpose_CONFIGURATION:
			returnstrings = append(returnstrings, "configuration")
		case sbom.Purpose_CONTAINER:
			returnstrings = append(returnstrings, "container")
		case sbom.Purpose_DATA:
			returnstrings = append(returnstrings, "data")
		case sbom.Purpose_DEVICE, sbom.Purpose_DEVICE_DRIVER:
			returnstrings = append(returnstrings, "device")
		case sbom.Purpose_DOCUMENTATION:
			returnstrings = append(returnstrings, "documentation")
		case sbom.Purpose_EVIDENCE:
			returnstrings = append(returnstrings, "evidence")
		case sbom.Purpose_EXECUTABLE:
			returnstrings = append(returnstrings, "executable")
		case sbom.Purpose_FILE:
			returnstrings = append(returnstrings, "file")
		case sbom.Purpose_FIRMWARE:
			returnstrings = append(returnstrings, "firmware")
		case sbom.Purpose_FRAMEWORK:
			returnstrings = append(returnstrings, "framework")
		case sbom.Purpose_INSTALL:
			returnstrings = append(returnstrings, "install")
		case sbom.Purpose_LIBRARY:
			returnstrings = append(returnstrings, "library")
		case sbom.Purpose_MANIFEST:
			returnstrings = append(returnstrings, "manifest")
		case sbom.Purpose_MACHINE_LEARNING_MODEL, sbom.Purpose_MODEL:
			returnstrings = append(returnstrings, "model")
		case sbom.Purpose_MODULE:
			returnstrings = append(returnstrings, "module")
		case sbom.Purpose_OPERATING_SYSTEM:
			returnstrings = append(returnstrings, "operatingSystem")
		case sbom.Purpose_PATCH:
			returnstrings = append(returnstrings, "patch")
		case sbom.Purpose_REQUIREMENT:
			returnstrings = append(returnstrings, "requirement")
		case sbom.Purpose_SOURCE:
			returnstrings = append(returnstrings, "source")
		case sbom.Purpose_SPECIFICATION:
			returnstrings = append(returnstrings, "specification")
		case sbom.Purpose_TEST:
			returnstrings = append(returnstrings, "test")
		case sbom.Purpose_OTHER, sbom.Purpose_PLATFORM:
			returnstrings = append(returnstrings, "other")

		default:
			// TODO(degradation): Non-matching primary purpose to component type mapping
		}
	}

	return returnstrings
}

// extRefTypeFromProtobomExtRef returns the SPDX3 external reference type from the
// corresponding protobom enumeration
func (spdx3 *SPDX3) extRefTypeFromProtobomExtRef(extRef *sbom.ExternalReference) string {
	switch extRef.Type {
	case sbom.ExternalReference_BINARY:
		return "binaryArtifact"
	case sbom.ExternalReference_BOWER:
		return "bower"
	case sbom.ExternalReference_BUILD_META:
		return "buildMeta"
	case sbom.ExternalReference_BUILD_SYSTEM:
		return "buildSystem"
	case sbom.ExternalReference_CERTIFICATION_REPORT:
		return "certificationReport"
	case sbom.ExternalReference_CHAT:
		return "chat"
	case sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT:
		return "componentAnalysisReport"
	case sbom.ExternalReference_DOCUMENTATION:
		return "documentation"
	case sbom.ExternalReference_DOWNLOAD:
		return "altDownloadLocation"
	case sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT:
		return "dynamicAnalysisReport"
	case sbom.ExternalReference_EOL_NOTICE:
		return "eolNotice"
	case sbom.ExternalReference_EXPORT_CONTROL_ASSESSMENT:
		return "exportControlAssessment"
	case sbom.ExternalReference_FUNDING:
		return "funding"
	case sbom.ExternalReference_ISSUE_TRACKER:
		return "issueTracker"
	case sbom.ExternalReference_LICENSE:
		return "license"
	case sbom.ExternalReference_MAILING_LIST:
		return "mailingList"
	case sbom.ExternalReference_MAVEN_CENTRAL:
		return "mavenCentral"
	case sbom.ExternalReference_METRICS:
		return "metrics"
	case sbom.ExternalReference_NPM:
		return "npm"
	case sbom.ExternalReference_NUGET:
		return "nuget"
	case sbom.ExternalReference_OTHER:
		return "other"
	case sbom.ExternalReference_PRIVACY_ASSESSMENT:
		return "privacyAssessment"
	case sbom.ExternalReference_PRODUCT_METADATA:
		return "productMetadata"
	case sbom.ExternalReference_PURCHASE_ORDER:
		return "purchaseOrder"
	case sbom.ExternalReference_QUALITY_ASSESSMENT_REPORT:
		return "qualityAssessmentReport"
	case sbom.ExternalReference_RELEASE_HISTORY:
		return "releaseHistory"
	case sbom.ExternalReference_RELEASE_NOTES:
		return "releaseNotes"
	case sbom.ExternalReference_RISK_ASSESSMENT:
		return "riskAssessment"
	case sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT:
		return "runtimeAnalysisReport"
	case sbom.ExternalReference_SECURE_SOFTWARE_ATTESTATION:
		return "secureSoftwareAttestation"
	case sbom.ExternalReference_SECURITY_ADVERSARY_MODEL:
		return "securityAdversaryModel"
	case sbom.ExternalReference_SECURITY_ADVISORY:
		return "securityAdvisory"
	case sbom.ExternalReference_SECURITY_FIX:
		return "securityFix"
	case sbom.ExternalReference_SECURITY_OTHER:
		return "securityOther"
	case sbom.ExternalReference_SECURITY_PENTEST_REPORT:
		return "securityPenTestReport"
	case sbom.ExternalReference_SECURITY_POLICY:
		return "securityPolicy"
	case sbom.ExternalReference_SECURITY_THREAT_MODEL:
		return "securityThreatModel"
	case sbom.ExternalReference_SOCIAL:
		return "socialMedia"
	case sbom.ExternalReference_SOURCE_ARTIFACT:
		return "sourceArtifact"
	case sbom.ExternalReference_STATIC_ANALYSIS_REPORT:
		return "staticAnalysisReport"
	case sbom.ExternalReference_SUPPORT:
		return "support"
	case sbom.ExternalReference_VCS:
		return "vcs"
	case sbom.ExternalReference_VULNERABILITY_DISCLOSURE_REPORT:
		return "vulnerabilityDisclosureReport"
	case sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT:
		return "vulnerabilityExploitabilityAssessment"
	case sbom.ExternalReference_WEBSITE:
		return "altWebPage"
	default:
		return "other"
	}
}
