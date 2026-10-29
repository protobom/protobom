package serializers

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	cdxformats "github.com/protobom/protobom/pkg/formats/cyclonedx"
	"github.com/protobom/protobom/pkg/licenselist"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Serializer = &CDX{}

// Precompiled regex for serialNumber validation
const serialNumberPattern = `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`

var (
	serialNumberRegex     *regexp.Regexp
	serialNumberRegexInit sync.Once

	// cdxMimeTypePattern is the shape the CycloneDX schema requires of a
	// component mime-type.
	cdxMimeTypePattern = regexp.MustCompile(`^[-+a-z0-9.]+/[-+a-z0-9.]+$`)
)

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

func (s *CDX) Serialize(bom *sbom.Document, serializeopts *native.SerializeOptions, rawopts interface{}) (interface{}, error) {
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

	doc.Version = cdxDocumentVersion(bom.Metadata.Version)

	// Add the document metadata
	md, err := buildMetadata(bom)
	if err != nil {
		return nil, fmt.Errorf("building metadata: %w", err)
	}
	doc.Metadata = md

	// Check if we have headless support on
	headless := serializeopts != nil && serializeopts.IsModEnabled(mod.CYCLONEDX_MULTIROOT_HEADLESS)

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

	// Reject documents with more than one root unless the caller opted into
	// the headless mod, which promotes all roots to top-level components.
	if l := len(bom.NodeList.RootElements); l > 1 && !headless {
		return nil, fmt.Errorf("unable to serialize multiroot (%d) cyclonedx, (mod.CYCLONEDX_MULTIROOT_HEADLESS disabled)", l)
	}

	// Convert all nodes to cdx components
	components := map[string]*cdx.Component{}
	for _, node := range bom.NodeList.Nodes {
		components[node.Id] = s.nodeToComponent(node)
	}

	// Index the direct targets of every node once, in the order the edges
	// state them, so the component tree is built in document order.
	children := indexChildren(bom.NodeList)

	// Apply the scope relationships to the components.
	applyScopeEdges(bom.NodeList, components)

	// Clear the protobom generated bomrefs
	clearAutoRefs(components)

	if headless && len(bom.NodeList.RootElements) > 1 {
		// Drop metadata.component entirely and promote each protobom root to
		// a top-level CycloneDX component, attaching its contained subtree.
		doc.Metadata.Component = nil

		seen := map[string]struct{}{}
		for _, rootID := range bom.NodeList.RootElements {
			seen[rootID] = struct{}{}
		}

		topComponents := []cdx.Component{}
		for _, rootID := range bom.NodeList.RootElements {
			rootComp, ok := components[rootID]
			if !ok {
				return nil, fmt.Errorf("integrity error: root component %q not found", rootID)
			}
			subtree, err := recurseComponentComponents(rootID, children, components, &seen)
			if err != nil {
				return nil, fmt.Errorf("building component tree for root %q: %w", rootID, err)
			}
			rootComp.Components = subtree
			topComponents = append(topComponents, *rootComp)
		}
		doc.Components = &topComponents
	} else {
		rootNode := bom.NodeList.GetNodeByID(bom.NodeList.RootElements[0])
		if rootNode == nil {
			return nil, fmt.Errorf("integrity error: root node %q not found", bom.NodeList.RootElements[0])
		}

		doc.Metadata.Component = s.nodeToComponent(rootNode)

		// Extract the component tree
		componentTree, err := recurseComponentComponents(
			rootNode.Id, children, components, &map[string]struct{}{rootNode.Id: {}},
		)
		if err != nil {
			return nil, fmt.Errorf("building component tree: %w", err)
		}
		doc.Components = componentTree
	}

	// Build the dependency graph:
	deps, err := buildDependencies(bom.NodeList, components)
	if err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}
	doc.Dependencies = &deps

	// TODO(degradation): the protobom document name has no equivalent field
	// in CycloneDX and is not written. A future mod could preserve it, for
	// example as a namespaced metadata property; it must not overwrite the
	// root component's name, which names the software, not the document.

	return doc, nil
}

// cdxDocumentVersion returns the CycloneDX document version a protobom
// version string states. CycloneDX counts revisions of a document with an
// integer of 1 or more, 1 being the default. A protobom version that is not
// such an integer cannot be written and yields the default: an empty one is
// the usual case, since formats without a revision counter leave it unset.
// TODO(degradation): a version that is not a positive integer is dropped.
func cdxDocumentVersion(version string) int {
	v, err := strconv.Atoi(strings.TrimSpace(version))
	if err != nil || v < 1 {
		return 1
	}
	return v
}

// applyScopeEdges projects the relationships carrying CycloneDX scope
// semantics back into the scope attribute of the (From) component.
func applyScopeEdges(nl *sbom.NodeList, components map[string]*cdx.Component) {
	for _, e := range nl.Edges {
		scope, ok := edgeTypeToScope(e.Type)
		if !ok {
			continue
		}
		// TODO(degradation): The CycloneDX scope is an attribute of the
		// component, not of the relationship. If a node relates to more
		// than one parent with different scope semantics, only one survives.
		if c, exists := components[e.From]; exists {
			c.Scope = scope
		}
	}
}

// edgeTypeToScope returns the CycloneDX component scope equivalent to a
// protobom edge type. It is the inverse of the unserializer scope mapping and
// also translates data originating in the equivalent SPDX relationships
// (OPTIONAL_COMPONENT_OF, DEV_DEPENDENCY_OF, RUNTIME_DEPENDENCY_OF).
func edgeTypeToScope(t sbom.Edge_Type) (cdx.Scope, bool) {
	switch t {
	case sbom.Edge_runtimeDependency:
		return cdx.ScopeRequired, true
	case sbom.Edge_optionalComponent:
		return cdx.ScopeOptional, true
	case sbom.Edge_devDependency:
		return cdx.ScopeExcluded, true
	default:
		return "", false
	}
}

func buildDependencies(nl *sbom.NodeList, components map[string]*cdx.Component) ([]cdx.Dependency, error) {
	ret := []cdx.Dependency{}
	for _, e := range nl.Edges {
		// Scope-carrying relationships surface as the scope attribute of
		// their components, they are not part of the dependency graph.
		if _, ok := edgeTypeToScope(e.Type); ok {
			continue
		}
		// Containment is structural data: it is already expressed through
		// the component nesting, so it does not belong in the dependency
		// graph. Writing it there would claim the parent depends on
		// everything it contains.
		if e.Type == sbom.Edge_contains {
			continue
		}
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
	serialNumberRegexInit.Do(func() {
		serialNumberRegex = regexp.MustCompile(serialNumberPattern)
	})
	return serialNumberRegex.MatchString(serial)
}

// indexChildren returns the direct targets of every node across all edge
// types, in the order the edges state them. A target is listed once, where
// it first appears.
func indexChildren(nl *sbom.NodeList) map[string][]string {
	children := map[string][]string{}
	listed := map[string]map[string]struct{}{}
	for _, e := range nl.Edges {
		if listed[e.From] == nil {
			listed[e.From] = map[string]struct{}{}
		}
		for _, id := range e.To {
			if _, ok := listed[e.From][id]; ok {
				continue
			}
			listed[e.From][id] = struct{}{}
			children[e.From] = append(children[e.From], id)
		}
	}
	return children
}

// recurseComponentComponents builds the component subtree under start: its
// direct targets, each with their own subtree, in the order the edges state
// them so the output is the same every time the document is written. A node
// already placed in the tree is not placed again.
func recurseComponentComponents(
	start string, children map[string][]string, components map[string]*cdx.Component, seen *map[string]struct{}, //nolint:gocritic
) (*[]cdx.Component, error) {
	ret := []cdx.Component{}

	// Claim this level's nodes before recursing, so a node reachable from
	// two siblings lands under the first one.
	level := []string{}
	for _, id := range children[start] {
		if _, ok := (*seen)[id]; ok {
			continue
		}
		if _, ok := components[id]; !ok {
			return nil, fmt.Errorf("unable to find component for node %q", id)
		}
		level = append(level, id)
		(*seen)[id] = struct{}{}
	}

	for _, id := range level {
		comps, err := recurseComponentComponents(id, children, components, seen)
		if err != nil {
			return nil, err
		}
		components[id].Components = comps
		ret = append(ret, *components[id])
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
			lifecycles = append(lifecycles, documentTypeToLifecycle(dt))
		}
		metadata.Lifecycles = &lifecycles
	}

	if len(doc.GetMetadata().GetTools()) > 0 {
		var tools []cdx.Tool //nolint:staticcheck
		for _, bomtool := range doc.GetMetadata().GetTools() {
			tools = append(tools, cdx.Tool{ //nolint:staticcheck // Tool is needed for older cdx versions
				Vendor:  bomtool.Vendor,
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

// documentTypeToLifecycle converts a protobom document type to a CycloneDX
// lifecycle entry. A lifecycle is either one of the predefined phases or a
// named entry with an optional description, never both. The types with a
// phase equivalent are written as that phase; the rest (OTHER, RUNTIME and
// an unset type) are written as a named lifecycle. When the type carries no
// name, the lowercased type name is used so the entry stays valid.
// TODO(degradation): the name and description of a type written as a phase
// are not written, the schema does not admit them next to a phase.
func documentTypeToLifecycle(dt *sbom.DocumentType) cdx.Lifecycle {
	if dt.Type != nil {
		if phase, ok := sbomTypeToPhase(*dt.Type); ok {
			return cdx.Lifecycle{Phase: phase}
		}
	}

	name := dt.GetName()
	if name == "" && dt.Type != nil {
		name = strings.ToLower(dt.Type.String())
	}

	return cdx.Lifecycle{
		Name:        name,
		Description: dt.GetDescription(),
	}
}

// sbomTypeToPhase returns the CycloneDX lifecycle phase equivalent to a
// protobom document type. The second return value is false when the type has
// no predefined phase (OTHER and RUNTIME).
func sbomTypeToPhase(t sbom.DocumentType_SBOMType) (cdx.LifecyclePhase, bool) {
	switch t {
	case sbom.DocumentType_BUILD:
		return cdx.LifecyclePhaseBuild, true
	case sbom.DocumentType_DESIGN:
		return cdx.LifecyclePhaseDesign, true
	case sbom.DocumentType_ANALYZED:
		return cdx.LifecyclePhasePostBuild, true
	case sbom.DocumentType_SOURCE:
		return cdx.LifecyclePhasePreBuild, true
	case sbom.DocumentType_DECOMISSION:
		return cdx.LifecyclePhaseDecommission, true
	case sbom.DocumentType_DEPLOYED:
		return cdx.LifecyclePhaseOperations, true
	case sbom.DocumentType_DISCOVERY:
		return cdx.LifecyclePhaseDiscovery, true
	default:
		return "", false
	}
}

// clearAutoRefs
// The last step of the CDX serialization recursively removes all autogenerated
// refs added by the protobom reader. These are added on CycloneDX ingestion
// to all nodes that don't have them. To maintain the closest fidelity, we
// clear their refs again before output to CDX
func clearAutoRefs(comps map[string]*cdx.Component) {
	for i := range comps {
		if strings.HasPrefix(comps[i].BOMRef, "protobom-") {
			// Read the flags from the autogen reference
			flags := strings.Split(comps[i].BOMRef, "--")
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

	licenseChoices := []cdx.LicenseChoice{}
	for _, l := range n.Licenses {
		licenseChoices = append(licenseChoices, protobomLicenseToCdx(l))
	}
	// From 1.6 on, CycloneDX can state the concluded license apart from the
	// declared ones through the license acknowledgement. A concluded license
	// that only restates the declared list is not written: the reader derives
	// it again from the declared entries, so writing it would add an entry
	// the source never had on every pass through CycloneDX.
	// TODO(degradation): below 1.6 the concluded license is not written.
	if s.statesConcludedLicense(n) {
		licenseChoices = append(licenseChoices, protobomConcludedLicenseToCdx(n.LicenseConcluded))
	}
	if len(licenseChoices) > 0 {
		licenses := cdx.Licenses(licenseChoices)
		c.Licenses = &licenses
	}

	// Hashes and identifiers are maps. They are written in the order of
	// their algorithm and type values so the output is stable.
	for _, algo := range slices.Sorted(maps.Keys(n.Hashes)) {
		cdxAlgo, err := s.protoHashAlgoToCdxAlgo(sbom.HashAlgorithm(algo))
		if err != nil {
			// TODO(degradation): Algorithm not supported in CDX
			continue
		}
		*c.Hashes = append(*c.Hashes, cdx.Hash{
			Algorithm: cdxAlgo,
			Value:     n.Hashes[algo],
		})
	}

	if n.ExternalReferences != nil {
		for _, er := range n.ExternalReferences {
			cdxRef := cdx.ExternalReference{
				URL:     er.Url,
				Comment: er.Comment,
				Type:    s.cdxExtRefType(er),
			}
			hashList := []cdx.Hash{}
			for _, protoAlgo := range slices.Sorted(maps.Keys(er.Hashes)) {
				cdxAlgo, err := s.protoHashAlgoToCdxAlgo(sbom.HashAlgorithm(protoAlgo))
				if err != nil {
					// TODO(degradation): Hash not supported
					continue
				}
				hashList = append(hashList, cdx.Hash{
					Algorithm: cdxAlgo,
					Value:     er.Hashes[protoAlgo],
				})
			}
			if len(hashList) > 0 {
				cdxRef.Hashes = &hashList
			}
			*c.ExternalReferences = append(*c.ExternalReferences, cdxRef)
		}
	}

	// The home and download URLs have no field of their own on a CycloneDX
	// component, they are stated as external references of type website and
	// distribution. A reference is only added when the node does not already
	// carry it, which is the case for data read from CycloneDX where the
	// unserializer keeps the reference when it holds more than the URL.
	s.addURLReference(c, n.UrlHome, sbom.ExternalReference_WEBSITE)
	s.addURLReference(c, n.UrlDownload, sbom.ExternalReference_DOWNLOAD)

	if n.Identifiers != nil {
		for _, idType := range slices.Sorted(maps.Keys(n.Identifiers)) {
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
			case int32(sbom.SoftwareIdentifierType_GITOID):
				// OmniBOR identifiers are gitoids. The field is a 1.6
				// addition, the encoder drops it for older versions.
				c.OmniborID = &[]string{n.Identifiers[idType]}
			}
		}
	}

	if n.Suppliers != nil && len(n.GetSuppliers()) > 0 {
		// TODO(degradation): CDX type Component only supports one Supplier while protobom supports multiple
		// TODO(degradation): The supplier's own email and phone have no
		// place on a CycloneDX organizational entity, and a person
		// supplier is written as an organization.

		nodesupplier := n.GetSuppliers()[0]
		oe := cdx.OrganizationalEntity{
			Name: nodesupplier.GetName(),
		}
		if nodesupplier.GetUrl() != "" {
			oe.URL = &[]string{nodesupplier.GetUrl()}
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

	if len(n.Originators) > 0 {
		// The originators map to the component authors, a 1.6 addition the
		// encoder drops for older versions.
		// TODO(degradation): an originator's URL and org flag cannot be
		// stated on a CycloneDX contact.
		var authors []cdx.OrganizationalContact
		for _, o := range n.Originators {
			authors = append(authors, cdx.OrganizationalContact{
				Name:  o.Name,
				Email: o.Email,
				Phone: o.Phone,
			})
		}
		c.Authors = &authors
	}

	c.Copyright = n.GetCopyright()

	// The content type is the component's mime-type. CycloneDX requires it
	// in lower case and shaped as type/subtype; media types are not case
	// sensitive, so the case is normalized rather than dropping the value.
	// TODO(degradation): a content type that is not shaped as a media type
	// cannot be written.
	if mimeType := strings.ToLower(strings.TrimSpace(n.ContentType)); cdxMimeTypePattern.MatchString(mimeType) {
		c.MIMEType = mimeType
	}

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

// addURLReference appends an external reference of the given type pointing to
// url, unless url is empty or the component already references it with the
// same type.
func (s *CDX) addURLReference(c *cdx.Component, location string, t sbom.ExternalReference_ExternalReferenceType) {
	if location == "" {
		return
	}
	cdxType := s.protobomExtRefTypeToCdxType(t)
	for _, er := range *c.ExternalReferences {
		if er.Type == cdxType && er.URL == location {
			return
		}
	}
	*c.ExternalReferences = append(*c.ExternalReferences, cdx.ExternalReference{
		URL:  location,
		Type: cdxType,
	})
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

// cdxExtRefType returns the CycloneDX type of a protobom external reference.
// It is protobomExtRefTypeToCdxType, except for the one type whose CycloneDX
// name depends on the reference's URL: a security policy is written as the
// RFC 9116 reference type only when it points at a security.txt file, which
// is what that type means. Any other security policy has no CycloneDX name.
func (s *CDX) cdxExtRefType(er *sbom.ExternalReference) cdx.ExternalReferenceType {
	if er.Type == sbom.ExternalReference_SECURITY_POLICY && isSecurityTxtURL(er.Url) {
		return cdx.ERTypeRFC9116
	}
	return s.protobomExtRefTypeToCdxType(er.Type)
}

// isSecurityTxtURL reports whether a URL points at a security.txt file as
// RFC 9116 locates it: at /.well-known/security.txt, or at /security.txt
// for the legacy location the RFC still admits.
func isSecurityTxtURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Path), "/security.txt")
}

// protobomExtRefTypeToCdxType translates between the protobom external reference
// identifiers and the CycloneDX equivalent types.
//
// A SECURITY_POLICY has no CycloneDX name of its own: the RFC 9116 type
// names a security.txt file specifically, so it is only written when the
// reference URL points at one (see cdxExtRefType).
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
	case sbom.ExternalReference_SOURCE_ARTIFACT:
		return cdx.ERTypeSourceDistribution
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

// protobomLicenseToCdx renders a single protobom license string as a CycloneDX
// license choice. CycloneDX only accepts a listed SPDX identifier in
// License.ID, so the string is placed by what it is:
//
//   - A license reference protobom minted from a CycloneDX license name
//     (see cdxformats.NamedLicenseRefPrefix) goes back to License.Name.
//   - Any other license reference came from an SPDX document and is emitted
//     through the Expression field, which takes any SPDX expression and so
//     preserves the reference as is.
//   - A compound SPDX expression is emitted through the Expression field too.
//   - A license in the SPDX License List goes to License.ID in its canonical
//     spelling, since the field is case sensitive.
//   - Any other bare license is not an identifier CycloneDX accepts and is
//     written as a license name.
//     TODO(degradation): the unserializer reads such a name back as a
//     marked license reference rather than the original string.
//
// The unserializer reads each form back into the same license slice (see
// licenseChoicesToLicenseList), which keeps the round trip.
func protobomLicenseToCdx(license string) cdx.LicenseChoice {
	if name, ok := cdxformats.LicenseNameFromRef(license); ok {
		return cdx.LicenseChoice{License: &cdx.License{Name: name}}
	}
	if cdxformats.IsLicenseRef(license) || isSPDXLicenseExpression(license) {
		return cdx.LicenseChoice{Expression: license}
	}
	if canonical, _, ok := licenselist.License(license); ok {
		return cdx.LicenseChoice{License: &cdx.License{ID: canonical}}
	}
	return cdx.LicenseChoice{License: &cdx.License{Name: license}}
}

// protobomConcludedLicenseToCdx renders the concluded license as a CycloneDX
// license choice marked with the concluded acknowledgement, which CycloneDX
// states inside the license object for a bare license and on the choice for
// an expression.
func protobomConcludedLicenseToCdx(license string) cdx.LicenseChoice {
	choice := protobomLicenseToCdx(license)
	if choice.License != nil {
		choice.License.Acknowledgement = cdx.LicenseAcknowledgementConcluded
	} else {
		ack := cdx.LicenseAcknowledgementConcluded
		choice.Acknowledgement = &ack
	}
	return choice
}

// statesConcludedLicense reports whether the node's concluded license has to
// be written as an acknowledged entry: the target version supports the
// acknowledgement and the concluded license says more than the declared list,
// that is, it differs from what the reader derives from the declared entries.
func (s *CDX) statesConcludedLicense(n *sbom.Node) bool {
	if n.LicenseConcluded == "" || !s.supportsLicenseAcknowledgment() {
		return false
	}
	return n.LicenseConcluded != cdxformats.DerivedConcludedLicense(n.Licenses)
}

// supportsLicenseAcknowledgment reports whether the CycloneDX version being
// written can mark a license with an acknowledgement (1.6 and later).
func (s *CDX) supportsLicenseAcknowledgment() bool {
	version, err := cdxformats.ParseVersion(s.version)
	return err == nil && version >= cdx.SpecVersion1_6
}

// isSPDXLicenseExpression reports whether a license string is a compound SPDX
// expression rather than a single identifier. SPDX identifiers never contain
// spaces, so the AND/OR/WITH operators and grouping parentheses only ever
// appear in expressions.
func isSPDXLicenseExpression(license string) bool {
	return strings.Contains(license, " AND ") ||
		strings.Contains(license, " OR ") ||
		strings.Contains(license, " WITH ") ||
		strings.ContainsAny(license, "()")
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
