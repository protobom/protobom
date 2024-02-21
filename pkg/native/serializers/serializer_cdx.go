package serializers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	cdxformats "github.com/bom-squad/protobom/pkg/formats/cyclonedx"
	"github.com/bom-squad/protobom/pkg/native"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

var _ native.Serializer = &CDX{}

const (
	stateKey state = "cyclonedx_serializer_state"
)

var (
	emptyRoot = cdx.Component{}
)

type (
	state string
	CDX   struct {
		version  string
		encoding string
	}
)

func NewCDX(version, encoding string) *CDX {
	return &CDX{
		version:  version,
		encoding: encoding,
	}
}

func (s *CDX) Serialize(bom *sbom.Document, _ *native.SerializeOptions, _ interface{}) (interface{}, error) {
	// Load the context with the CDX value. We initialize a context here
	// but we should get it as part of the method to capture cancelations
	// from the CLI or REST API.
	state := newSerializerCDXState()
	ctx := context.WithValue(context.Background(), stateKey, state)

	doc := cdx.NewBOM()
	doc.SerialNumber = bom.Metadata.Id
	ver, err := strconv.Atoi(bom.Metadata.Version)
	// TODO(deprecation): If version does not parse to int, there's data loss here.
	if err == nil {
		doc.Version = ver
	}

	metadata := cdx.Metadata{
		Component:  &cdx.Component{},
		Lifecycles: &[]cdx.Lifecycle{},
	}

	doc.Metadata = &metadata
	doc.Components = &[]cdx.Component{}
	doc.Dependencies = &[]cdx.Dependency{}

	// Check if the protobom has no root elements:
	if bom.NodeList.RootElements == nil || len(bom.NodeList.RootElements) == 0 {
		// Empty (nodeless) document
		if len(bom.NodeList.Nodes) == 0 {
			return doc, nil
		}
		// If we have nodes but no roots, then we error as the graph
		// cannot be traversed
		return nil, fmt.Errorf("unable to build cyclonedx document, no root nodes found")
	}

	selectedRoots, err := selectRootsCdx(ctx, bom)
	if err != nil {
		return nil, err
	}
	bom.NodeList.RootElements = selectedRoots
	root, err := s.root(ctx, bom)
	if err != nil {
		return nil, err
	}

	doc.Metadata.Component = root

	if err := s.componentsMaps(ctx, bom); err != nil {
		return nil, err
	}

	for _, dt := range bom.Metadata.DocumentTypes {
		var lfc cdx.Lifecycle

		if dt.Type == nil {
			lfc.Name = *dt.Name
			lfc.Description = *dt.Description
		} else {
			lfc.Phase, err = sbomTypeToPhase(dt)
			if err != nil {
				return nil, err
			}
		}

		*doc.Metadata.Lifecycles = append(*doc.Metadata.Lifecycles, lfc)
	}

	if bom.Metadata != nil && len(bom.GetMetadata().GetAuthors()) > 0 {
		var authors []cdx.OrganizationalContact
		for _, bomauthor := range bom.GetMetadata().GetAuthors() {
			authors = append(authors, cdx.OrganizationalContact{
				Name:  bomauthor.Name,
				Email: bomauthor.Email,
				Phone: bomauthor.Phone,
			})
		}
		metadata.Authors = &authors
	}

	if bom.Metadata != nil && len(bom.GetMetadata().GetTools()) > 0 {
		var tools []cdx.Tool //nolint:staticcheck
		for _, bomtool := range bom.GetMetadata().GetTools() {
			tools = append(tools, cdx.Tool{ //nolint:staticcheck // Tool is needed for older cdx versions
				Name:    bomtool.Name,
				Version: bomtool.Version,
			})
		}
		metadata.Tools = &cdx.ToolsChoice{
			Tools: &tools,
		}
	}

	if bom.Metadata != nil && len(bom.GetMetadata().GetName()) > 0 {
		doc.Metadata.Component.Name = bom.GetMetadata().GetName()
	}

	deps, err := s.dependencies(ctx, bom)
	if err != nil {
		return nil, err
	}
	doc.Dependencies = &deps

	components := state.components()
	clearAutoRefs(&components)
	doc.Components = &components

	return doc, nil
}

func selectRootsCdx(ctx context.Context, bom *sbom.Document) ([]string, error) {
	var selectedRoots []string
	roots := bom.NodeList.GetRootElements()
	switch len(roots) {
	case 0:
		return selectedRoots, fmt.Errorf("no root provided")
	case 1:
		selectedRoots = append(selectedRoots, roots[0])
	default:
		// Leave root empty will push all roots as components.
	}

	return selectedRoots, nil
}

func (s *CDX) root(ctx context.Context, bom *sbom.Document) (*cdx.Component, error) {
	if len(bom.NodeList.GetRootElements()) > 1 {
		return nil, fmt.Errorf("CDX can only include a single root")
	}

	if len(bom.NodeList.GetRootElements()) > 0 {
		id := bom.NodeList.GetRootElements()[0]
		rootNode := bom.NodeList.GetNodeByID(id)
		if rootNode == nil {
			return nil, fmt.Errorf("integrity error: root node %q not found", bom.NodeList.RootElements[0])
		}
		rootsComp := s.nodeToComponent(rootNode)
		return rootsComp, nil
	} else {
		return &emptyRoot, nil
	}
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
func clearAutoRefs(comps *[]cdx.Component) {
	for i := range *comps {
		if strings.HasPrefix((*comps)[i].BOMRef, "protobom-") {
			flags := strings.Split((*comps)[i].BOMRef, "--")
			if strings.Contains(flags[0], "-auto") {
				(*comps)[i].BOMRef = ""
			}
		}
		if (*comps)[i].Components != nil && len(*(*comps)[i].Components) != 0 {
			clearAutoRefs((*comps)[i].Components)
		}
	}
}

func (s *CDX) componentsMaps(ctx context.Context, bom *sbom.Document) error {
	state, err := getCDXState(ctx)
	if err != nil {
		return fmt.Errorf("reading state: %w", err)
	}

	for _, n := range bom.NodeList.Nodes {
		comp := s.nodeToComponent(n)
		if comp == nil {
			// Error? Warn?
			continue
		}
		state.componentsDict[comp.BOMRef] = comp
	}

	return nil
}

// NOTE dependencies function modifies the components dictionary
func (s *CDX) dependencies(ctx context.Context, bom *sbom.Document) ([]cdx.Dependency, error) {
	var dependencies []cdx.Dependency
	state, err := getCDXState(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}

	for _, e := range bom.NodeList.Edges {
		e := e
		if _, ok := state.addedDict[e.From]; ok {
			continue
		}

		if _, ok := state.componentsDict[e.From]; !ok {
			logrus.Info("serialize")
			return nil, fmt.Errorf("unable to find component %s", e.From)
		}

		// In this example, we tree-ify all components related with a
		// "contains" relationship. This is just an opinion for the demo
		// and it is something we can parameterize
		switch e.Type {
		case sbom.Edge_contains:
			// Make sure we have the target component
			for _, targetID := range e.To {
				state.addedDict[targetID] = struct{}{}
				if _, ok := state.componentsDict[targetID]; !ok {
					return nil, fmt.Errorf("unable to locate node %s", targetID)
				}

				if state.componentsDict[e.From].Components == nil {
					state.componentsDict[e.From].Components = &[]cdx.Component{}
				}
				*state.componentsDict[e.From].Components = append(*state.componentsDict[e.From].Components, *state.componentsDict[targetID])
			}

		case sbom.Edge_dependsOn:
			// Add to the dependency tree
			targetStrings := []string{}
			depListCheck := map[string]struct{}{}
			for _, targetID := range e.To {
				// Add entries to dependency only once.
				if _, ok := depListCheck[targetID]; ok {
					continue
				}

				if _, ok := state.componentsDict[targetID]; !ok {
					return nil, fmt.Errorf("unable to locate node %s", targetID)
				}

				state.addedDict[targetID] = struct{}{}
				depListCheck[targetID] = struct{}{}
				targetStrings = append(targetStrings, targetID)
			}
			dependencies = append(dependencies, cdx.Dependency{
				Ref:          e.From,
				Dependencies: &targetStrings,
			})
		default:
			// TODO(degradation) here, we would document how relationships are lost
			logrus.Warnf(
				"node %s is related with %s to %d other nodes, data will be lost",
				e.From, e.Type, len(e.To),
			)
		}
	}

	return dependencies, nil
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

	if n.Licenses != nil && len(n.Licenses) > 0 {
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

	if n.Hashes != nil && len(n.Hashes) > 0 {
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

	if len(n.GetCopyright()) > 0 {
		c.Copyright = n.GetCopyright()
	}

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

	if _, ok := doc.(*cdx.BOM); !ok {
		return errors.New("document is not a cyclonedx bom")
	}

	if err := encoder.EncodeVersion(doc.(*cdx.BOM), version); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}

type serializerCDXState struct {
	addedDict      map[string]struct{}
	componentsDict map[string]*cdx.Component
}

func newSerializerCDXState() *serializerCDXState {
	return &serializerCDXState{
		addedDict:      map[string]struct{}{},
		componentsDict: map[string]*cdx.Component{},
	}
}

func (s *serializerCDXState) components() []cdx.Component {
	components := []cdx.Component{}
	for _, c := range s.componentsDict {
		if _, ok := s.addedDict[c.BOMRef]; ok {
			continue
		}
		components = append(components, *c)
	}

	return components
}

func getCDXState(ctx context.Context) (*serializerCDXState, error) {
	dm, ok := ctx.Value(stateKey).(*serializerCDXState)
	if !ok {
		return nil, errors.New("unable to cast serializer state from context")
	}
	return dm, nil
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
