package serializers

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	cdxformats "github.com/protobom/protobom/pkg/formats/cyclonedx"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Serializer = &CDX{}

// Precompiled regex for serialNumber validation
const serialNumberPattern = `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`

var serialNumberRegex *regexp.Regexp

type (
	CDX struct {
		version  string
		encoding string
	}
)

// CDXOptions groups the configuration options for the CycloneDX serializer.
type CDXOptions struct {
	// GenerateSerialNumber instructs the serializer to generate a random URN
	// when the protobom document has an empty ID or a deterministic UUID when
	// it contains an incompatible string.
	//
	// When false, the serializer will return an error when the document ID is
	// empty or not a serialNumber-compatible string.
	GenerateSerialNumber bool
}

// Validate checks if the serializer options are
func (o *CDXOptions) Validate() error {
	// This is a noop for now
	return nil
}

var DefaultCDXOptions = CDXOptions{
	GenerateSerialNumber: true,
}

func NewCDX(version, encoding string) *CDX {
	return &CDX{
		version:  version,
		encoding: encoding,
	}
}

func (s *CDX) Serialize(bom *sbom.Document, _ *native.SerializeOptions, rawopts interface{}) (interface{}, error) {
	// Load the context with the CDX value. We initialize a context here
	// but we should get it as part of the method to capture cancelations
	// from the CLI or REST API.

	opts := DefaultCDXOptions
	if rawopts != nil {
		var ok bool
		if opts, ok = rawopts.(CDXOptions); !ok {
			return nil, fmt.Errorf("error casting SPDX 2.3 options")
		}
	}
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating CDX options: %w", err)
	}

	doc := cdx.NewBOM()
	doc.SerialNumber = bom.Metadata.Id

	if doc.SerialNumber == "" || !isValidCycloneDXSerialNumberFormat(doc.SerialNumber) {
		if opts.GenerateSerialNumber {
			if bom.Metadata.Id != "" {
				doc.SerialNumber = "urn:uuid:" + uuid.NewSHA1(uuid.MustParse(sbom.NamespaceUUID), []byte(bom.Metadata.Id)).String()
			} else {
				doc.SerialNumber = "urn:uuid:" + uuid.NewString()
			}
		} else {
			return nil, fmt.Errorf("unable to generate serialNumber, document ID is blank or invalid")
		}
	}

	ver, err := strconv.Atoi(bom.Metadata.Version)
	// TODO(deprecation): If version does not parse to int, there's data loss here.
	if err == nil {
		doc.Version = ver
	}

	// Add the document metadata
	md, err := buildMetadata(bom)
	if err != nil {
		return nil, fmt.Errorf("building metadata: %w", err)
	}
	doc.Metadata = md

	// Check if the protobom has no root elements:
	if len(bom.NodeList.RootElements) == 0 {
		// Empty (nodeless) document
		if len(bom.NodeList.Nodes) == 0 {
			return doc, nil
		}
		// If we have nodes but no roots, then we error as the graph
		// cannot be traversed
		return nil, fmt.Errorf("unable to build cyclonedx document, no root nodes found")
	}

	// .. or has too many root elements:

	// TODO(deprecation): If there are more root nodes we need to hack them
	// into the CycloneDX graph or error
	if l := len(bom.NodeList.RootElements); l > 1 {
		return nil, fmt.Errorf("unable to serialize multiroot cyclonedx, document has %d root nodes", l)
	}

	// Convert all nodes to cdx cmponents
	components := map[string]*cdx.Component{}
	for _, node := range bom.NodeList.Nodes {
		components[node.Id] = s.nodeToComponent(node)
	}

	// CLear the protobom generated bomrefs
	clearAutoRefs(components)

	rootNode := bom.NodeList.GetNodeByID(bom.NodeList.RootElements[0])
	if rootNode == nil {
		return nil, fmt.Errorf("integrity error: root node %q not found", bom.NodeList.RootElements[0])
	}

	doc.Metadata.Component = s.nodeToComponent(rootNode)

	// Extract the component tree
	componentTree, err := recurseComponentComponents(
		rootNode.Id, bom.NodeList, components, &map[string]struct{}{rootNode.Id: {}},
	)
	if err != nil {
		return nil, fmt.Errorf("building component tree: %w", err)
	}
	doc.Components = componentTree

	// Build the dependency graph:
	deps, err := buildDependencies(bom.NodeList, components)
	if err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}
	doc.Dependencies = &deps

	if bom.Metadata != nil && bom.GetMetadata().GetName() != "" {
		doc.Metadata.Component.Name = bom.GetMetadata().GetName()
	}

	return doc, nil
}

func buildDependencies(nl *sbom.NodeList, components map[string]*cdx.Component) ([]cdx.Dependency, error) {
	ret := []cdx.Dependency{}
	for _, e := range nl.Edges {
		if _, ok := components[e.From]; !ok {
			return nil, fmt.Errorf("node %q not found in components list", e.From)
		}

		// If the src does not have a bomref, skip
		if components[e.From].BOMRef == "" {
			continue
		}
		deps := []string{}
		dep := cdx.Dependency{
			Ref: components[e.From].BOMRef,
		}

		for _, id := range e.To {
			if _, ok := components[id]; !ok {
				return nil, fmt.Errorf("node %q not found in components list", id)
			}
			if components[id].BOMRef == "" {
				continue
			}
			deps = append(deps, components[id].BOMRef)
		}
		dep.Dependencies = &deps
		// Only add the tree if it has destinations
		if len(deps) > 0 {
			ret = append(ret, dep)
		}
	}
	return ret, nil
}

// isValidCycloneDXSerialNumber validates serial id against regex pattern
func isValidCycloneDXSerialNumberFormat(serial string) bool {
	if serialNumberRegex == nil {
		serialNumberRegex = regexp.MustCompile(serialNumberPattern)
	}
	return serialNumberRegex.MatchString(serial)
}

func recurseComponentComponents(
	start string, nl *sbom.NodeList, components map[string]*cdx.Component, seen *map[string]struct{}, //nolint:gocritic
) (*[]cdx.Component, error) {
	// FIrst, well add the first level ones and then recurse
	ret := []cdx.Component{}
	descendants := nl.NodeDescendants(start, 1)
	if len(descendants.Edges) == 0 {
		return &ret, nil
	}

	protoIDToComp := map[string]*cdx.Component{}

	// First add the nodes to the top
	for _, id := range descendants.Edges[0].To {
		if _, ok := (*seen)[id]; ok {
			continue
		}
		if _, ok := components[id]; !ok {
			return nil, fmt.Errorf("unable to find component for node %q", id)
		}
		protoIDToComp[id] = components[id]
		(*seen)[id] = struct{}{}
	}

	// Now cycle them again and recurse
	for id := range protoIDToComp {
		comps, err := recurseComponentComponents(id, nl, components, seen)
		if err != nil {
			return nil, err
		}
		protoIDToComp[id].Components = comps
	}

	// Assemble the return slice
	for _, comp := range protoIDToComp {
		ret = append(ret, *comp)
	}
	return &ret, nil
}

// buildMetadata builds the sbom metadata
func buildMetadata(doc *sbom.Document) (*cdx.Metadata, error) {
	metadata := cdx.Metadata{
		Component: &cdx.Component{},
	}

	if doc.Metadata == nil {
		return nil, fmt.Errorf("protobom metadata is nil")
	}

	if len(doc.GetMetadata().GetAuthors()) > 0 {
		var authors []cdx.OrganizationalContact
		for _, bomauthor := range doc.GetMetadata().GetAuthors() {
			authors = append(authors, cdx.OrganizationalContact{
				Name:  bomauthor.Name,
				Email: bomauthor.Email,
				Phone: bomauthor.Phone,
			})
		}
		metadata.Authors = &authors
	}

	if len(doc.Metadata.DocumentTypes) > 0 {
		lifecycles := []cdx.Lifecycle{}

		for _, dt := range doc.Metadata.DocumentTypes {
			var lfc cdx.Lifecycle
			var err error
			if dt.Type == nil {
				lfc.Name = *dt.Name
				lfc.Description = *dt.Description
			} else {
				lfc.Phase, err = sbomTypeToPhase(dt)
				if err != nil {
					return nil, err
				}
			}

			lifecycles = append(lifecycles, lfc)
		}
		metadata.Lifecycles = &lifecycles
	}

	if len(doc.GetMetadata().GetTools()) > 0 {
		var tools []cdx.Tool //nolint:staticcheck
		for _, bomtool := range doc.GetMetadata().GetTools() {
			tools = append(tools, cdx.Tool{ //nolint:staticcheck // Tool is needed for older cdx versions
				Name:    bomtool.Name,
				Version: bomtool.Version,
			})
		}
		metadata.Tools = &cdx.ToolsChoice{
			Tools: &tools,
		}
	}

	if doc.GetMetadata().GetDate() != nil {
		t := doc.GetMetadata().GetDate().AsTime()
		metadata.Timestamp = t.Format(time.RFC3339)
	}

	return &metadata, nil
}

// sbomTypeToPhase converts a SBOM document type to a CDX lifecycle phase
func sbomTypeToPhase(dt *sbom.DocumentType) (cdx.LifecyclePhase, error) {
	switch *dt.Type {
	case sbom.DocumentType_BUILD:
		return cdx.LifecyclePhaseBuild, nil
	case sbom.DocumentType_DESIGN:
		return cdx.LifecyclePhaseDesign, nil
	case sbom.DocumentType_ANALYZED:
		return cdx.LifecyclePhasePostBuild, nil
	case sbom.DocumentType_SOURCE:
		return cdx.LifecyclePhasePreBuild, nil
	case sbom.DocumentType_DECOMISSION:
		return cdx.LifecyclePhaseDecommission, nil
	case sbom.DocumentType_DEPLOYED:
		return cdx.LifecyclePhaseOperations, nil
	case sbom.DocumentType_DISCOVERY:
		return cdx.LifecyclePhaseDiscovery, nil
	case sbom.DocumentType_OTHER:
		return cdx.LifecyclePhase(strings.ToLower(*dt.Name)), nil
	}
	// TODO(option): Dont err but assign to type OTHER
	return "", fmt.Errorf("unknown document type %s", *dt.Name)
}

// clearAutoRefs
// The last step of the CDX serialization recursively removes all autogenerated
// refs added by the protobom reader. These are added on CycloneDX ingestion
// to all nodes that don't have them. To maintain the closest fidelity, we
// clear their refs again before output to CDX
func clearAutoRefs(comps map[string]*cdx.Component) {
	for i := range comps {
		if strings.HasPrefix((comps)[i].BOMRef, "protobom-") {
			// Read the flags from the autogen reference
			flags := strings.Split((comps)[i].BOMRef, "--")
			if strings.Contains(flags[0], "-auto") {
				comps[i].BOMRef = ""
			}
		}
	}
}

// nodeToComponent converts a node in protobuf to a CycloneDX component
func (s *CDX) nodeToComponent(n *sbom.Node) *cdx.Component {
	if n == nil {
		return nil
	}

	c := &cdx.Component{
		BOMRef:             n.Id,
		Name:               n.Name,
		Version:            n.Version,
		Description:        n.Description,
		Hashes:             &[]cdx.Hash{},
		ExternalReferences: &[]cdx.ExternalReference{},
	}

	if n.Type == sbom.Node_FILE {
		c.Type = cdx.ComponentTypeFile
	} else if len(n.PrimaryPurpose) > 0 {
		componentType, err := s.purposeToComponentType(n.PrimaryPurpose[0])
		if err == nil {
			c.Type = componentType
		}
		// TODO(degradation): Multiple PrimaryPurpose in protobom.Node, but
		// cdx.Component only allows single Type so we are using the first
	}

	if len(n.Licenses) > 0 {
		var licenseChoices []cdx.LicenseChoice
		var licenses cdx.Licenses
		for _, l := range n.Licenses {
			licenseChoices = append(licenseChoices, cdx.LicenseChoice{
				License: &cdx.License{
					ID: l,
				},
			})
		}

		licenses = licenseChoices
		c.Licenses = &licenses
	}

	if len(n.Hashes) > 0 {
		for algo, hash := range n.Hashes {
			cdxAlgo, err := s.protoHashAlgoToCdxAlgo(sbom.HashAlgorithm(algo))
			if err != nil {
				// TODO(degradation): Algorithm not supported in CDX
				continue
			}
			*c.Hashes = append(*c.Hashes, cdx.Hash{
				Algorithm: cdxAlgo,
				Value:     hash,
			})
		}
	}

	if n.ExternalReferences != nil {
		for _, er := range n.ExternalReferences {
			cdxRef := cdx.ExternalReference{
				URL:     er.Url,
				Comment: er.Comment,
				Type:    s.protobomExtRefTypeToCdxType(er.Type),
			}
			hashList := []cdx.Hash{}
			for protoAlgo, val := range er.Hashes {
				cdxAlgo, err := s.protoHashAlgoToCdxAlgo(sbom.HashAlgorithm(protoAlgo))
				if err != nil {
					// TODO(degradation): Hash not supported
					continue
				}
				hashList = append(hashList, cdx.Hash{
					Algorithm: cdxAlgo,
					Value:     val,
				})
			}
			if len(hashList) > 0 {
				cdxRef.Hashes = &hashList
			}
			*c.ExternalReferences = append(*c.ExternalReferences, cdxRef)
		}
	}

	if n.Identifiers != nil {
		for idType := range n.Identifiers {
			switch idType {
			case int32(sbom.SoftwareIdentifierType_PURL):
				c.PackageURL = n.Identifiers[idType]
			case int32(sbom.SoftwareIdentifierType_CPE23):
				c.CPE = n.Identifiers[idType]
			case int32(sbom.SoftwareIdentifierType_CPE22):
				// TODO(degradation): Only one CPE is supported in CDX
				if c.CPE == "" {
					c.CPE = n.Identifiers[idType]
				}
			}
		}
	}

	if n.Suppliers != nil && len(n.GetSuppliers()) > 0 {
		// TODO(degradation): CDX type Component only supports one Supplier while protobom supports multiple

		nodesupplier := n.GetSuppliers()[0]
		oe := cdx.OrganizationalEntity{
			Name: nodesupplier.GetName(),
		}
		if nodesupplier.Contacts != nil {
			var contacts []cdx.OrganizationalContact
			for _, nodecontact := range nodesupplier.GetContacts() {
				newcontact := cdx.OrganizationalContact{
					Name:  nodecontact.GetName(),
					Email: nodecontact.GetEmail(),
					Phone: nodecontact.GetPhone(),
				}
				contacts = append(contacts, newcontact)
			}
			oe.Contact = &contacts
		}
		c.Supplier = &oe
	}

	c.Copyright = n.GetCopyright()

	properties := []cdx.Property{}
	for _, p := range n.Properties {
		properties = append(properties, cdx.Property{
			Name:  p.Name,
			Value: p.Data,
		})
	}
	c.Properties = &properties

	return c
}

// Render calls the official CDX serializer to render the BOM into a specific version
func (s *CDX) Render(doc interface{}, wr io.Writer, o *native.RenderOptions, _ interface{}) error {
	if doc == nil {
		return errors.New("document is nil")
	}

	version, err := cdxformats.ParseVersion(s.version)
	if err != nil {
		return fmt.Errorf("getting CDX version: %w", err)
	}

	encoding, err := cdxformats.ParseEncoding(s.encoding)
	if err != nil {
		return fmt.Errorf("getting CDX encoding: %w", err)
	}

	encoder := cdx.NewBOMEncoder(wr, encoding)
	encoder.SetPretty(true)

	cdxdoc, ok := doc.(*cdx.BOM)
	if !ok {
		return errors.New("document is not a cyclonedx bom")
	}

	if err := encoder.EncodeVersion(cdxdoc, version); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}

// protobomExtRefTypeToCdxType translates between the protobom external reference
// identifiers and the CycloneDX equivalent types.
func (s *CDX) protobomExtRefTypeToCdxType(protoExtRefType sbom.ExternalReference_ExternalReferenceType) cdx.ExternalReferenceType {
	switch protoExtRefType {
	case sbom.ExternalReference_ATTESTATION:
		return cdx.ERTypeAttestation
	case sbom.ExternalReference_BOM:
		return cdx.ERTypeBOM
	case sbom.ExternalReference_BUILD_META:
		return cdx.ERTypeBuildMeta
	case sbom.ExternalReference_BUILD_SYSTEM:
		return cdx.ERTypeBuildSystem
	case sbom.ExternalReference_CERTIFICATION_REPORT:
		return cdx.ERTypeCertificationReport
	case sbom.ExternalReference_CHAT:
		return cdx.ERTypeChat
	case sbom.ExternalReference_CODIFIED_INFRASTRUCTURE:
		return cdx.ERTypeCodifiedInfrastructure
	case sbom.ExternalReference_COMPONENT_ANALYSIS_REPORT:
		return cdx.ERTypeComponentAnalysisReport
	case sbom.ExternalReference_CONFIGURATION:
		return cdx.ExternalReferenceType("configuration")
	case sbom.ExternalReference_DISTRIBUTION_INTAKE:
		return cdx.ERTypeDistributionIntake
	case sbom.ExternalReference_DOWNLOAD:
		return cdx.ERTypeDistribution
	case sbom.ExternalReference_DOCUMENTATION:
		return cdx.ERTypeDocumentation
	case sbom.ExternalReference_DYNAMIC_ANALYSIS_REPORT:
		return cdx.ERTypeDynamicAnalysisReport
	case sbom.ExternalReference_EVIDENCE:
		return cdx.ExternalReferenceType("evidence")
	case sbom.ExternalReference_FORMULATION:
		return cdx.ExternalReferenceType("formulation")
	case sbom.ExternalReference_ISSUE_TRACKER:
		return cdx.ERTypeIssueTracker
	case sbom.ExternalReference_LICENSE:
		return cdx.ERTypeLicense
	case sbom.ExternalReference_LOG:
		return cdx.ExternalReferenceType("log")
	case sbom.ExternalReference_MAILING_LIST:
		return cdx.ERTypeMailingList
	case sbom.ExternalReference_MATURITY_REPORT:
		return cdx.ERTypeMaturityReport
	case sbom.ExternalReference_MODEL_CARD:
		return cdx.ExternalReferenceType("model-card")
	case sbom.ExternalReference_OTHER:
		return cdx.ERTypeOther
	case sbom.ExternalReference_POAM:
		return cdx.ExternalReferenceType("poam")
	case sbom.ExternalReference_QUALITY_METRICS:
		return cdx.ERTypeQualityMetrics
	case sbom.ExternalReference_RELEASE_NOTES:
		return cdx.ERTypeReleaseNotes
	case sbom.ExternalReference_RISK_ASSESSMENT:
		return cdx.ERTypeRiskAssessment
	case sbom.ExternalReference_RUNTIME_ANALYSIS_REPORT:
		return cdx.ERTypeRuntimeAnalysisReport
	case sbom.ExternalReference_SECURITY_ADVERSARY_MODEL:
		return cdx.ERTypeAdversaryModel
	case sbom.ExternalReference_SECURITY_ADVISORY:
		return cdx.ERTypeAdvisories
	case sbom.ExternalReference_SECURITY_CONTACT:
		return cdx.ERTypeSecurityContact
	case sbom.ExternalReference_SECURITY_PENTEST_REPORT:
		return cdx.ERTypePentestReport
	case sbom.ExternalReference_SECURITY_THREAT_MODEL:
		return cdx.ERTypeThreatModel
	case sbom.ExternalReference_SOCIAL:
		return cdx.ERTypeSocial
	case sbom.ExternalReference_STATIC_ANALYSIS_REPORT:
		return cdx.ERTypeStaticAnalysisReport
	case sbom.ExternalReference_SUPPORT:
		return cdx.ERTypeSupport
	case sbom.ExternalReference_VCS:
		return cdx.ERTypeVCS
	case sbom.ExternalReference_VULNERABILITY_ASSERTION:
		return cdx.ERTypeVulnerabilityAssertion
	case sbom.ExternalReference_VULNERABILITY_EXPLOITABILITY_ASSESSMENT:
		return cdx.ERTypeExploitabilityStatement
	case sbom.ExternalReference_WEBSITE:
		return cdx.ERTypeWebsite
	default:
		return cdx.ERTypeOther
	}
}

// protoHashAlgoToCdxAlgo converts the protobom algorithm to the CDX
// algorithm string.
// TODO(degradation): The use of the following algorithms will result in
// data loss when rendering to CycloneDX 1.4: ADLER32 MD4 MD6 SHA224
// Also, HashAlgorithm_UNKNOWN also means data loss.
func (s *CDX) protoHashAlgoToCdxAlgo(protoAlgo sbom.HashAlgorithm) (cdx.HashAlgorithm, error) {
	switch protoAlgo {
	case sbom.HashAlgorithm_MD5:
		return cdx.HashAlgoMD5, nil
	case sbom.HashAlgorithm_SHA1:
		return cdx.HashAlgoSHA1, nil
	case sbom.HashAlgorithm_SHA256:
		return cdx.HashAlgoSHA256, nil
	case sbom.HashAlgorithm_SHA384:
		return cdx.HashAlgoSHA384, nil
	case sbom.HashAlgorithm_SHA512:
		return cdx.HashAlgoSHA512, nil
	case sbom.HashAlgorithm_SHA3_256:
		return cdx.HashAlgoSHA3_256, nil
	case sbom.HashAlgorithm_SHA3_384:
		return cdx.HashAlgoSHA3_384, nil
	case sbom.HashAlgorithm_SHA3_512:
		return cdx.HashAlgoSHA3_512, nil
	case sbom.HashAlgorithm_BLAKE2B_256:
		return cdx.HashAlgoBlake2b_256, nil
	case sbom.HashAlgorithm_BLAKE2B_384:
		return cdx.HashAlgoBlake2b_384, nil
	case sbom.HashAlgorithm_BLAKE2B_512:
		return cdx.HashAlgoBlake2b_512, nil
	case sbom.HashAlgorithm_BLAKE3:
		return cdx.HashAlgoBlake3, nil
	}

	// TODO(degradation): Unknow algorithms err here. We could silently not.
	// TODO(options): Sink all unknows to UNKNOWN
	return "", fmt.Errorf("hash algorithm %q not supported by cyclonedx", protoAlgo)
}

// purposeToComponentType converts from a protobom enumerated purpose to
// a CycloneDC component type
func (s *CDX) purposeToComponentType(purpose sbom.Purpose) (cdx.ComponentType, error) {
	switch purpose {
	case sbom.Purpose_APPLICATION, sbom.Purpose_EXECUTABLE, sbom.Purpose_INSTALL:
		return cdx.ComponentTypeApplication, nil
	case sbom.Purpose_CONTAINER:
		return cdx.ComponentTypeContainer, nil
	case sbom.Purpose_DATA, sbom.Purpose_BOM, sbom.Purpose_CONFIGURATION, sbom.Purpose_DOCUMENTATION, sbom.Purpose_EVIDENCE, sbom.Purpose_MANIFEST, sbom.Purpose_REQUIREMENT, sbom.Purpose_SPECIFICATION, sbom.Purpose_TEST, sbom.Purpose_OTHER:
		return cdx.ComponentTypeData, nil
	case sbom.Purpose_DEVICE:
		return cdx.ComponentTypeDevice, nil
	case sbom.Purpose_DEVICE_DRIVER:
		return cdx.ComponentTypeDeviceDriver, nil
	case sbom.Purpose_FILE, sbom.Purpose_PATCH, sbom.Purpose_SOURCE, sbom.Purpose_ARCHIVE:
		return cdx.ComponentTypeFile, nil
	case sbom.Purpose_FIRMWARE:
		return cdx.ComponentTypeFirmware, nil
	case sbom.Purpose_FRAMEWORK:
		return cdx.ComponentTypeFramework, nil
	case sbom.Purpose_LIBRARY, sbom.Purpose_MODULE:
		return cdx.ComponentTypeLibrary, nil
	case sbom.Purpose_MACHINE_LEARNING_MODEL, sbom.Purpose_MODEL:
		return cdx.ComponentTypeMachineLearningModel, nil
	case sbom.Purpose_OPERATING_SYSTEM:
		return cdx.ComponentTypeOS, nil
	case sbom.Purpose_PLATFORM:
		return cdx.ComponentTypePlatform, nil
	}

	return "", fmt.Errorf("document purpose %q not supported", purpose)
}
