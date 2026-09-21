// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/base"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/simplelicensing"
	"github.com/carabiner-dev/spdx3/profiles/software"
	spdx3types "github.com/carabiner-dev/spdx3/types"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Serializer = &SPDX3{}

// The type discriminators of the SPDX 3 values written inline rather than as
// elements of the graph.
const (
	spdx3ExternalIdentifier = "ExternalIdentifier"
	spdx3ExternalRef        = "ExternalRef"
	spdx3LicenseExpression  = "simplelicensing_LicenseExpression"
)

// SPDX3 serializes protobom documents to SPDX 3.0.1.
//
// A node's list of declared licenses is written as a single expression
// joining them with AND, which is how the SPDX 3 reader takes it apart
// again. Entries that are compound expressions themselves are wrapped in
// parentheses so each keeps its meaning.
type SPDX3 struct{}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

type SPDX3Options struct {
	// GenerateDocumentID causes the serializer to generate a document
	// identifier when the protobom has none.
	GenerateDocumentID bool

	// ListCollectionElements causes the document to name its members with
	// the element[] property, as well as saying what it is about with
	// rootElement.
	//
	// It is off by default. The property is optional, the graph already
	// carries every element, and naming them again roughly doubles the
	// references in the document. Most documents in the wild leave it out
	// so we chose to not enable this by default. Turn it on for a consumer
	// that reads the collection rather than the graph.
	ListCollectionElements bool

	// LicenseListVersion is the version of the SPDX License List the
	// license expressions refer to, in the major.minor.patch form SPDX 3
	// asks for (for example "3.27.0"). When set, it is written on every
	// license expression. Protobom does not carry the version, so it is
	// empty by default and left out of the document.
	//
	// The License List itself is versioned major.minor, as in "3.27", so
	// such a version is completed to "3.27.0". Serialize returns an error
	// for any version that is neither that nor a semantic version.
	LicenseListVersion string
}

var DefaultSPDX3Options = SPDX3Options{
	GenerateDocumentID:     true,
	ListCollectionElements: false,
	LicenseListVersion:     "",
}

// Render writes the SPDX 3 document. The indent of the render options is not
// used: the SPDX 3 serialization is JSON-LD, which the library that models it
// writes itself.
func (s *SPDX3) Render(doc any, wr io.Writer, _ *native.RenderOptions, _ any) error {
	env, ok := doc.(*spdx3.Envelope)
	if !ok {
		return errors.New("unable to cast doc as an SPDX 3 envelope")
	}
	if err := (&spdx3.Renderer{}).Render(env, wr); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}
	return nil
}

// Serialize takes a protobom and returns an SPDX 3.0.1 document.
func (s *SPDX3) Serialize(bom *sbom.Document, _ *native.SerializeOptions, rawopts any) (any, error) {
	if bom == nil {
		return nil, errors.New("document is nil, unable to serialize to SPDX 3.0.1")
	}
	if bom.Metadata == nil {
		return nil, errors.New("document metadata is nil, unable to serialize to SPDX 3.0.1")
	}

	opts := DefaultSPDX3Options
	if rawopts != nil {
		var ok bool
		if opts, ok = rawopts.(SPDX3Options); !ok {
			return nil, fmt.Errorf("error casting SPDX 3 options")
		}
	}

	var err error

	opts.LicenseListVersion, err = normalizeLicenseListVersion(opts.LicenseListVersion)
	if err != nil {
		return nil, fmt.Errorf("validating SPDX 3 options: %w", err)
	}

	namespace, err := spdxNamespaceFromProtobomID(SPDX23Options{
		GenerateDocumentID: opts.GenerateDocumentID,
	}, bom.Metadata.Id)
	if err != nil {
		return nil, fmt.Errorf("serializing SPDX namespace: %w", err)
	}

	env := spdx3.NewEnvelope()
	t := &spdx3Translator{
		namespace: namespace,
		env:       env,
		nodeList:  bom.NodeList,
		opts:      opts,
		licenses:  map[string]spdx3types.Node{},
	}

	// The agents and tools the document credits, which its creation
	// information points at.
	creation := t.creationInfo(bom.Metadata)

	// The elements themselves, and the licenses they are under.
	for _, node := range bom.NodeList.Nodes {
		element, err := t.node(node)
		if err != nil {
			return nil, fmt.Errorf("converting node %q: %w", node.Id, err)
		}
		env.Graph.AddNode(element)
		if err := t.nodeLicenses(node, element); err != nil {
			return nil, fmt.Errorf("converting node %q: %w", node.Id, err)
		}
	}

	// The relationships between them.
	for _, edge := range bom.NodeList.Edges {
		t.edge(edge)
	}

	// The bill of materials itself. SPDX 3 separates the document, which is
	// the file and says how it was made, from the bill of materials it
	// carries, which is a subject in its own right: what kind of bill it is
	// belongs to the software, not to the file.
	sbomElement := software.NewSbom(t.newID("sbom"), documentTypesToSPDX3(bom.Metadata.DocumentTypes)...)
	for _, id := range bom.NodeList.RootElements {
		sbomElement.AddRootElement(spdx3types.NodeRef{ID: t.elementID(id)})
	}
	env.Graph.AddNode(sbomElement)

	// And the document that holds it, naming what it is about.
	document := core.NewSpdxDocument(namespace)
	document.Name = bom.Metadata.Name
	document.Comment = bom.Metadata.Comment
	document.ProfileConformance = []core.ProfileIdentifierType{
		core.ProfileIdentifierTypeCore,
		core.ProfileIdentifierTypeSoftware,
		core.ProfileIdentifierTypeSimpleLicensing,
	}
	document.AddRootElement(sbomElement)
	env.Graph.AddNode(document)

	// A document names what it is about twice: with rootElement, and with a
	// describes relationship. Both are how the tools that write SPDX 3 do it,
	// and a reader that only understands one of them still finds its way in.
	env.Graph.Relate(
		t.newID("relationship"), document,
		core.RelationshipTypeDescribes, sbomElement,
	)

	// Listed once everything else is in place, so the collection names all of
	// its members and not only those built before the document.
	if opts.ListCollectionElements {
		for _, node := range env.Graph {
			if _, isElement := node.(core.ElementDescendant); isElement && node != document {
				document.AddElement(spdx3types.NodeRef{ID: node.GetSPDXID()})
			}
		}
	}

	// Said once, and shared by every element that has none of its own.
	env.Graph.SetCreationInfo(creation)

	return env, nil
}

// spdx3Translator carries what converting one document needs.
type spdx3Translator struct {
	namespace string
	env       *spdx3.Envelope
	nodeList  *sbom.NodeList
	opts      SPDX3Options
	counter   int

	// licenses holds the license element written for each distinct
	// expression, so nodes under the same license share one.
	licenses map[string]spdx3types.Node
}

// elementID returns an identifier for an element. SPDX3 identifies elements
// with an IRI, so an identifier that is not one is taken to name an element of
// this document and is resolved against its namespace.
func (t *spdx3Translator) elementID(id string) string {
	if id == "" {
		return ""
	}
	if strings.Contains(id, "://") || strings.HasPrefix(id, "urn:") {
		return id
	}
	return fmt.Sprintf("%s#%s", t.namespace, id)
}

// newID mints an identifier for an element protobom has no identifier for,
// such as a relationship or a license expression.
func (t *spdx3Translator) newID(kind string) string {
	t.counter++
	return fmt.Sprintf("%s#%s-%d", t.namespace, kind, t.counter)
}

// creationInfo builds the document's creation information, adding the agents
// and tools it credits to the graph.
func (t *spdx3Translator) creationInfo(md *sbom.Metadata) *core.CreationInfo {
	created := time.Now()
	if md.Date != nil {
		created = md.Date.AsTime()
	}

	creation := core.NewCreationInfo(created)

	for _, author := range md.Authors {
		creation.CreatedBy = append(creation.CreatedBy, t.agent(author))
	}

	// Record protobom itself, as the SPDX 2.3 serializer does, with the
	// version of the protobom module rather than that of the program
	// embedding it.
	self := core.NewTool(t.newID("tool"), protobomToolName())
	t.env.Graph.AddNode(self)
	creation.CreatedUsing = append(creation.CreatedUsing, self)

	for _, tool := range md.Tools {
		// The document already credits protobom above, so an entry for it
		// read from an earlier document is not repeated. Without this, every
		// read and write cycle would add another.
		if isProtobomTool(tool.Name, tool.Version) {
			continue
		}
		name := tool.Name
		if tool.Version != "" {
			name = fmt.Sprintf("%s-%s", tool.Name, tool.Version)
		}
		// TODO(degradation): a tool's vendor has nowhere to go in SPDX 3.
		element := core.NewTool(t.newID("tool"), name)
		t.env.Graph.AddNode(element)
		creation.CreatedUsing = append(creation.CreatedUsing, element)
	}

	// An SPDX 3 document must state who created it, so credit protobom, as
	// the software agent that wrote the document, when the protobom names
	// nobody. The predefined SpdxOrganization is not used: it stands for the
	// SPDX project, which did not create the document.
	if len(creation.CreatedBy) == 0 {
		creation.CreatedBy = append(creation.CreatedBy, t.agent(&sbom.Person{
			Name:            protospdx.ProtobomName,
			IsSoftwareAgent: true,
		}))
	}

	return creation
}

// agent converts a protobom person to the SPDX 3 agent modelling them.
func (t *spdx3Translator) agent(person *sbom.Person) core.AgentDescendant {
	id := t.newID("agent")
	var node *core.Node
	var agent core.AgentDescendant

	switch {
	case person.IsOrg:
		organization := core.NewOrganization(id, person.Name)
		node, agent = &organization.Node, organization
	case person.IsSoftwareAgent:
		// Something acting on its own behalf, such as a scanner or a build
		// system, which SPDX 3 has a class of its own for.
		selfActing := core.NewSoftwareAgent(id, person.Name)
		node, agent = &selfActing.Node, selfActing
	default:
		individual := core.NewPerson(id, person.Name)
		node, agent = &individual.Node, individual
	}

	if person.Email != "" {
		node.ExternalIdentifier = append(node.ExternalIdentifier, core.ExternalIdentifier{
			Type:                   spdx3ExternalIdentifier,
			ExternalIdentifierType: core.ExternalIdentifierTypeEmail,
			Identifier:             person.Email,
		})
	}
	if person.Url != "" {
		node.ExternalIdentifier = append(node.ExternalIdentifier, core.ExternalIdentifier{
			Type:                   spdx3ExternalIdentifier,
			ExternalIdentifierType: core.ExternalIdentifierTypeUrlScheme,
			Identifier:             person.Url,
		})
	}
	// TODO(degradation): a person's phone number and contacts are lost.

	t.env.Graph.AddNode(agent)
	return agent
}

// node converts a protobom node to the software element modelling it.
func (t *spdx3Translator) node(n *sbom.Node) (core.ElementDescendant, error) {
	switch n.Type {
	case sbom.Node_PACKAGE:
		return t.pkg(n), nil
	case sbom.Node_FILE:
		return t.file(n), nil
	default:
		return nil, fmt.Errorf("unknown node type %q", n.Type)
	}
}

func (t *spdx3Translator) pkg(n *sbom.Node) *software.Package {
	p := software.NewPackage(t.elementID(n.Id), n.Name)
	t.artifact(n, &p.Artifact)

	p.PackageVersion = n.Version
	p.DownloadLocation = n.UrlDownload
	p.HomePage = n.UrlHome
	p.SourceInfo = n.SourceInfo
	p.CopyrightText = n.Copyright
	p.AttributionText = n.Attribution
	p.PackageUrl = string(n.Purl())
	p.PrimaryPurpose, p.AdditionalPurpose = purposesToSPDX3(n.PrimaryPurpose)

	// TODO(degradation): SPDX 3 has no package file name. It says the same
	// with a File element related to the package by hasDistributionArtifact,
	// which would add a node to the graph that the protobom does not have.

	// The verification code is derived from the package's files rather than
	// carried in the protobom, so it is computed as the document is written.
	if code := packageVerificationCode(t.nodeList, n); code != "" {
		p.VerifiedUsing = append(p.VerifiedUsing, &core.PackageVerificationCode{
			IntegrityMethod: core.IntegrityMethod{
				PreNode: base.PreNode{Type: core.PackageVerificationCodeClass},
			},
			Algorithm: core.HashAlgorithmSha1,
			HashValue: code,
		})
	}

	return p
}

func (t *spdx3Translator) file(n *sbom.Node) *software.File {
	name := n.Name
	if n.FileName != "" {
		name = n.FileName
	}
	f := software.NewFile(t.elementID(n.Id), name)
	t.artifact(n, &f.Artifact)

	f.CopyrightText = n.Copyright
	f.AttributionText = n.Attribution

	// SPDX 3 replaced the SPDX 2 file types with the file's purpose and its
	// media type, so each file type is carried into whichever of the two
	// says the same thing. What the node states itself comes first.
	purposes, contentType := fileTypesToSPDX3(n.FileTypes)
	f.PrimaryPurpose, f.AdditionalPurpose = purposesToSPDX3(n.PrimaryPurpose, purposes...)
	// A media type is written only when it is shaped as one, type/subtype,
	// as SPDX 3 requires.
	f.ContentType = contentType
	if mediaTypePattern.MatchString(n.ContentType) {
		f.ContentType = n.ContentType
	}

	return f
}

// mediaTypePattern is the shape SPDX 3 requires of a media type.
var mediaTypePattern = regexp.MustCompile(`^[^/]+/[^/]+$`)

// licenseListVersionPattern is the semantic version SPDX 3 requires of a
// License List version, and shortVersionPattern the major.minor version the
// License List is published under.
var (
	licenseListVersionPattern = regexp.MustCompile(
		`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
			`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
			`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
	)
	shortVersionPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)$`)
)

// normalizeLicenseListVersion returns a License List version in the form SPDX
// 3 requires, completing a major.minor version with a zero patch level, and
// an error if it cannot.
func normalizeLicenseListVersion(version string) (string, error) {
	version = strings.TrimSpace(version)
	switch {
	case version == "", licenseListVersionPattern.MatchString(version):
		return version, nil
	case shortVersionPattern.MatchString(version):
		return version + ".0", nil
	default:
		return "", fmt.Errorf("invalid license list version %q, must be major.minor.patch", version)
	}
}

// artifact fills in what every software element carries, whatever its kind.
func (t *spdx3Translator) artifact(n *sbom.Node, a *core.Artifact) {
	a.Comment = n.Comment
	a.Summary = n.Summary
	a.Description = n.Description

	if n.BuildDate != nil {
		a.BuiltTime = spdx3types.NewDateTime(n.BuildDate.AsTime())
	}
	if n.ReleaseDate != nil {
		a.ReleaseTime = spdx3types.NewDateTime(n.ReleaseDate.AsTime())
	}
	if n.ValidUntilDate != nil {
		a.ValidUntilTime = spdx3types.NewDateTime(n.ValidUntilDate.AsTime())
	}

	for _, supplier := range n.Suppliers {
		// TODO(degradation): SPDX 3 names a single supplier, so any after
		// the first are lost.
		a.SuppliedBy = t.agent(supplier)
		break
	}
	for _, originator := range n.Originators {
		a.OriginatedBy = append(a.OriginatedBy, t.agent(originator))
	}

	// The hashes and identifiers are maps, so they are written in the order
	// of their keys to keep the output the same from one run to the next.
	for _, algo := range slices.Sorted(maps.Keys(n.Hashes)) {
		name := sbom.HashAlgorithm(algo).ToSPDX3()
		if name == "" {
			// TODO(degradation): the algorithm has no SPDX 3 name.
			continue
		}
		a.VerifiedUsing = append(a.VerifiedUsing, core.NewHash(core.HashAlgorithm(name), n.Hashes[algo]))
	}

	for _, idType := range slices.Sorted(maps.Keys(n.Identifiers)) {
		name := identifierTypeToSPDX3(sbom.SoftwareIdentifierType(idType))
		if name == "" {
			continue
		}
		a.ExternalIdentifier = append(a.ExternalIdentifier, core.ExternalIdentifier{
			Type:                   spdx3ExternalIdentifier,
			ExternalIdentifierType: name,
			Identifier:             n.Identifiers[idType],
		})
	}

	for _, ref := range n.ExternalReferences {
		// A reference without a URL points nowhere, and an empty locator
		// is not one.
		if ref == nil || ref.Url == "" {
			continue
		}
		a.ExternalRef = append(a.ExternalRef, core.ExternalRef{
			Type:            spdx3ExternalRef,
			ExternalRefType: core.ExternalRefType(externalRefTypeToSPDX3(ref)),
			Locator:         []string{ref.Url},
			Comment:         ref.Comment,
		})
	}

	// TODO(degradation): a node's properties have no home in SPDX 3 short of
	// an extension, which protobom has no way to describe.
}

// nodeLicenses states what a node is licensed under, which SPDX 3 says with
// a relationship to a license rather than with a field.
func (t *spdx3Translator) nodeLicenses(n *sbom.Node, element core.ElementDescendant) error {
	add := func(expression string, relType core.RelationshipType) {
		if license := t.license(expression); license != nil {
			t.env.Graph.Relate(t.newID("relationship"), element, relType, license)
		}
	}

	add(n.LicenseConcluded, core.RelationshipTypeHasConcludedLicense)

	// Protobom carries a list of declared licenses, which SPDX 3 states as
	// one expression. The list is read as licenses that all apply, so they
	// are joined with AND, and compound entries are bracketed to keep their
	// meaning.
	declared, err := protospdx.JoinLicenses(n.Licenses, protospdx.OperatorAND)
	if err != nil {
		return fmt.Errorf("joining declared licenses: %w", err)
	}
	add(declared, core.RelationshipTypeHasDeclaredLicense)

	// TODO(degradation): a node's license comments have nowhere to go.
	return nil
}

// license returns the license element stating an expression. The elements
// are shared: each distinct expression is written once, however many nodes
// it licenses. NONE and NOASSERTION are the individuals the specification
// predefines for them, which documents reference without writing out.
func (t *spdx3Translator) license(expression string) spdx3types.Node {
	expression = strings.TrimSpace(expression)
	switch {
	case expression == "":
		return nil
	case strings.EqualFold(expression, protospdx.NONE):
		return spdx3types.NodeRef{ID: protospdx.SPDX3NoneLicenseIRI}
	case strings.EqualFold(expression, protospdx.NOASSERTION):
		return spdx3types.NodeRef{ID: protospdx.SPDX3NoAssertionLicenseIRI}
	}

	if license, ok := t.licenses[expression]; ok {
		return spdx3types.NodeRef{ID: license.GetSPDXID()}
	}

	license := &simplelicensing.LicenseExpression{
		AnyLicenseInfo: simplelicensing.AnyLicenseInfo{Element: core.Element{Node: core.Node{
			PreNode: base.PreNode{
				SPDXID: t.newID("license"),
				Type:   spdx3LicenseExpression,
			},
		}}},
		LicenseExpression:  expression,
		LicenseListVersion: t.opts.LicenseListVersion,
	}
	t.env.Graph.AddNode(license)
	t.licenses[expression] = license
	return license
}

// edge converts a protobom edge to the relationship, or relationships, that
// say the same thing in SPDX 3.
func (t *spdx3Translator) edge(e *sbom.Edge) {
	mapping, ok := edgeTypeToSPDX3[e.Type]
	if !ok || mapping.relType == "" {
		// TODO(degradation): the edge has no SPDX 3 relationship type.
		return
	}

	from := spdx3types.NodeRef{ID: t.elementID(e.From)}
	to := make([]spdx3types.Node, 0, len(e.To))
	for _, id := range e.To {
		to = append(to, spdx3types.NodeRef{ID: t.elementID(id)})
	}

	if !mapping.invert {
		t.relate(mapping, from, to...)
		return
	}

	// SPDX 3 dropped most of the inverse relationship types SPDX 2 had, so
	// an edge stating one is turned around. An edge naming several targets
	// becomes one relationship per target, since each is now the source.
	for _, target := range to {
		t.relate(mapping, target, from)
	}
}

func (t *spdx3Translator) relate(mapping spdx3Relationship, from spdx3types.Node, to ...spdx3types.Node) {
	relationship := t.env.Graph.Relate(t.newID("relationship"), from, mapping.relType, to...)
	if mapping.scope == "" {
		return
	}

	// A relationship that only holds during part of an element's life is a
	// LifecycleScopedRelationship in SPDX 3.
	scoped := &core.LifecycleScopedRelationship{
		Relationship: *relationship,
		Scope:        mapping.scope,
	}
	scoped.Type = core.LifecycleScopedRelationshipClass
	t.env.Graph[len(t.env.Graph)-1] = scoped
}

// spdx3Relationship is what an edge becomes in SPDX 3.
type spdx3Relationship struct {
	relType core.RelationshipType
	// invert says the edge runs the other way round in SPDX 3, which drops
	// most of the inverse relationship types SPDX 2 defined.
	invert bool
	// scope is set where SPDX 3 says with a lifecycle scope what SPDX 2 said
	// with a relationship type of its own, such as a build dependency.
	scope core.LifecycleScopeType
}

// edgeTypeToSPDX3 maps protobom's edges, whose names and directions are those
// of SPDX 2, onto the SPDX 3 relationship vocabulary. The two are not the
// same: SPDX 3 renamed most types, dropped the inverse of nearly all of them,
// and replaced the dependency and tool variants with a lifecycle scope.
var edgeTypeToSPDX3 = map[sbom.Edge_Type]spdx3Relationship{
	// Same name, same direction.
	sbom.Edge_contains:   {relType: core.RelationshipTypeContains},
	sbom.Edge_dependsOn:  {relType: core.RelationshipTypeDependsOn},
	sbom.Edge_describes:  {relType: core.RelationshipTypeDescribes},
	sbom.Edge_generates:  {relType: core.RelationshipTypeGenerates},
	sbom.Edge_other:      {relType: core.RelationshipTypeOther},
	sbom.Edge_ancestor:   {relType: core.RelationshipTypeAncestorOf},
	sbom.Edge_descendant: {relType: core.RelationshipTypeDescendantOf},

	// Renamed, same direction.
	sbom.Edge_distributionArtifact: {relType: core.RelationshipTypeHasDistributionArtifact},
	sbom.Edge_dynamicLink:          {relType: core.RelationshipTypeHasDynamicLink},
	sbom.Edge_staticLink:           {relType: core.RelationshipTypeHasStaticLink},
	sbom.Edge_prerequisite:         {relType: core.RelationshipTypeHasPrerequisite},

	// The inverse types SPDX 3 dropped: stated the other way round.
	sbom.Edge_amends:              {relType: core.RelationshipTypeAmendedBy, invert: true},
	sbom.Edge_contained_by:        {relType: core.RelationshipTypeContains, invert: true},
	sbom.Edge_copy:                {relType: core.RelationshipTypeCopiedTo, invert: true},
	sbom.Edge_dataFile:            {relType: core.RelationshipTypeHasDataFile, invert: true},
	sbom.Edge_dependencyManifest:  {relType: core.RelationshipTypeHasDependencyManifest, invert: true},
	sbom.Edge_dependencyOf:        {relType: core.RelationshipTypeDependsOn, invert: true},
	sbom.Edge_describedBy:         {relType: core.RelationshipTypeDescribes, invert: true},
	sbom.Edge_documentation:       {relType: core.RelationshipTypeHasDocumentation, invert: true},
	sbom.Edge_example:             {relType: core.RelationshipTypeHasExample, invert: true},
	sbom.Edge_expandedFromArchive: {relType: core.RelationshipTypeExpandsTo, invert: true},
	sbom.Edge_fileAdded:           {relType: core.RelationshipTypeHasAddedFile, invert: true},
	sbom.Edge_fileDeleted:         {relType: core.RelationshipTypeHasDeletedFile, invert: true},
	sbom.Edge_generatedFrom:       {relType: core.RelationshipTypeGenerates, invert: true},
	sbom.Edge_metafile:            {relType: core.RelationshipTypeHasMetadata, invert: true},
	sbom.Edge_optionalComponent:   {relType: core.RelationshipTypeHasOptionalComponent, invert: true},
	sbom.Edge_optionalDependency:  {relType: core.RelationshipTypeHasOptionalDependency, invert: true},
	sbom.Edge_packages:            {relType: core.RelationshipTypePackagedBy, invert: true},
	sbom.Edge_patch:               {relType: core.RelationshipTypePatchedBy, invert: true},
	sbom.Edge_prerequisiteFor:     {relType: core.RelationshipTypeHasPrerequisite, invert: true},
	sbom.Edge_providedDependency:  {relType: core.RelationshipTypeHasProvidedDependency, invert: true},
	sbom.Edge_requirementFor:      {relType: core.RelationshipTypeHasRequirement, invert: true},
	sbom.Edge_specificationFor:    {relType: core.RelationshipTypeHasSpecification, invert: true},
	sbom.Edge_test:                {relType: core.RelationshipTypeHasTest, invert: true},
	sbom.Edge_testCase:            {relType: core.RelationshipTypeHasTestCase, invert: true},
	sbom.Edge_variant:             {relType: core.RelationshipTypeHasVariant, invert: true},

	// What SPDX 2 said with a relationship type of its own, SPDX 3 says with
	// dependsOn or usesTool and the lifecycle scope it holds during.
	sbom.Edge_buildDependency:   {relType: core.RelationshipTypeDependsOn, invert: true, scope: core.LifecycleScopeTypeBuild},
	sbom.Edge_devDependency:     {relType: core.RelationshipTypeDependsOn, invert: true, scope: core.LifecycleScopeTypeDevelopment},
	sbom.Edge_runtimeDependency: {relType: core.RelationshipTypeDependsOn, invert: true, scope: core.LifecycleScopeTypeRuntime},
	sbom.Edge_testDependency:    {relType: core.RelationshipTypeDependsOn, invert: true, scope: core.LifecycleScopeTypeTest},
	sbom.Edge_buildTool:         {relType: core.RelationshipTypeUsesTool, invert: true, scope: core.LifecycleScopeTypeBuild},
	sbom.Edge_devTool:           {relType: core.RelationshipTypeUsesTool, invert: true, scope: core.LifecycleScopeTypeDevelopment},
	sbom.Edge_testTool:          {relType: core.RelationshipTypeUsesTool, invert: true, scope: core.LifecycleScopeTypeTest},

	// TODO(degradation): SPDX 3 has no relationship for a file modified from
	// another, so modifiedBy is the closest thing to what protobom means.
	sbom.Edge_fileModified: {relType: core.RelationshipTypeModifiedBy},
}

// documentTypesToSPDX3 names the kinds of bill of materials a document is.
func documentTypesToSPDX3(types []*sbom.DocumentType) []software.SbomType {
	names := []software.SbomType{}
	for _, dt := range types {
		if dt == nil || dt.Type == nil {
			continue
		}
		// TODO(degradation): a document type's name and description have no
		// home in SPDX 3, which names the kind and nothing else.
		switch *dt.Type {
		case sbom.DocumentType_DESIGN:
			names = append(names, software.SbomTypeDesign)
		case sbom.DocumentType_SOURCE:
			names = append(names, software.SbomTypeSource)
		case sbom.DocumentType_BUILD:
			names = append(names, software.SbomTypeBuild)
		case sbom.DocumentType_ANALYZED:
			names = append(names, software.SbomTypeAnalyzed)
		case sbom.DocumentType_DEPLOYED:
			names = append(names, software.SbomTypeDeployed)
		case sbom.DocumentType_RUNTIME:
			names = append(names, software.SbomTypeRuntime)
		default:
			// TODO(degradation): SPDX 3 has no kind for OTHER, DISCOVERY or
			// DECOMISSION, the last two of which come from CycloneDX.
		}
	}
	return names
}

// identifierTypeToSPDX3 returns the SPDX 3 external identifier type naming a
// protobom software identifier.
func identifierTypeToSPDX3(t sbom.SoftwareIdentifierType) core.ExternalIdentifierType {
	switch t {
	case sbom.SoftwareIdentifierType_PURL:
		return core.ExternalIdentifierTypePackageUrl
	case sbom.SoftwareIdentifierType_CPE22:
		return core.ExternalIdentifierTypeCpe22
	case sbom.SoftwareIdentifierType_CPE23:
		return core.ExternalIdentifierTypeCpe23
	case sbom.SoftwareIdentifierType_GITOID:
		return core.ExternalIdentifierTypeGitoid
	default:
		return ""
	}
}

// purposesToSPDX3 splits protobom's purposes into the one SPDX 3 calls
// primary and the rest, which it calls additional. Any extra purposes, such
// as those a file's types imply, follow protobom's own, and a purpose is
// named once however many times it is stated.
func purposesToSPDX3(purposes []sbom.Purpose, extra ...software.SoftwarePurpose) (primary software.SoftwarePurpose, additional []software.SoftwarePurpose) {
	names := []software.SoftwarePurpose{}
	for _, p := range purposes {
		if name := purposeToSPDX3(p); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	for _, name := range extra {
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	return names[0], names[1:]
}

// fileTypesToSPDX3 carries SPDX 2 file types into the purposes and the media
// type SPDX 3 replaced them with, following the specification's migration
// guide. The purposes are returned in the order the types are listed.
//
// TODO(degradation): AUDIO, IMAGE and VIDEO name a family of media types
// rather than one, and SPDX a choice of two, so they are not carried over.
func fileTypesToSPDX3(fileTypes []string) (purposes []software.SoftwarePurpose, contentType string) {
	for _, fileType := range fileTypes {
		switch strings.ToUpper(strings.TrimSpace(fileType)) {
		case "ARCHIVE":
			purposes = append(purposes, software.SoftwarePurposeArchive)
		case "SOURCE":
			purposes = append(purposes, software.SoftwarePurposeSource)
		case "APPLICATION":
			purposes = append(purposes, software.SoftwarePurposeApplication)
		case "DOCUMENTATION":
			purposes = append(purposes, software.SoftwarePurposeDocumentation)
		case spdxOther:
			purposes = append(purposes, software.SoftwarePurposeOther)
		case "BINARY":
			contentType = cmp.Or(contentType, "application/octet-stream")
		case "TEXT":
			contentType = cmp.Or(contentType, "text/plain")
		}
	}
	return purposes, contentType
}

func purposeToSPDX3(p sbom.Purpose) software.SoftwarePurpose {
	switch p {
	case sbom.Purpose_APPLICATION:
		return software.SoftwarePurposeApplication
	case sbom.Purpose_ARCHIVE:
		return software.SoftwarePurposeArchive
	case sbom.Purpose_BOM:
		return software.SoftwarePurposeBom
	case sbom.Purpose_CONFIGURATION:
		return software.SoftwarePurposeConfiguration
	case sbom.Purpose_CONTAINER:
		return software.SoftwarePurposeContainer
	case sbom.Purpose_DATA:
		return software.SoftwarePurposeData
	case sbom.Purpose_DEVICE, sbom.Purpose_DEVICE_DRIVER:
		return software.SoftwarePurposeDevice
	case sbom.Purpose_DOCUMENTATION:
		return software.SoftwarePurposeDocumentation
	case sbom.Purpose_EVIDENCE:
		return software.SoftwarePurposeEvidence
	case sbom.Purpose_EXECUTABLE:
		return software.SoftwarePurposeExecutable
	case sbom.Purpose_FILE:
		return software.SoftwarePurposeFile
	case sbom.Purpose_FIRMWARE:
		return software.SoftwarePurposeFirmware
	case sbom.Purpose_FRAMEWORK:
		return software.SoftwarePurposeFramework
	case sbom.Purpose_INSTALL:
		return software.SoftwarePurposeInstall
	case sbom.Purpose_LIBRARY:
		return software.SoftwarePurposeLibrary
	case sbom.Purpose_MANIFEST:
		return software.SoftwarePurposeManifest
	case sbom.Purpose_MACHINE_LEARNING_MODEL, sbom.Purpose_MODEL:
		return software.SoftwarePurposeModel
	case sbom.Purpose_MODULE:
		return software.SoftwarePurposeModule
	case sbom.Purpose_OPERATING_SYSTEM:
		return software.SoftwarePurposeOperatingSystem
	case sbom.Purpose_PATCH:
		return software.SoftwarePurposePatch
	case sbom.Purpose_REQUIREMENT:
		return software.SoftwarePurposeRequirement
	case sbom.Purpose_SOURCE:
		return software.SoftwarePurposeSource
	case sbom.Purpose_SPECIFICATION:
		return software.SoftwarePurposeSpecification
	case sbom.Purpose_TEST:
		return software.SoftwarePurposeTest
	case sbom.Purpose_OTHER, sbom.Purpose_PLATFORM:
		return software.SoftwarePurposeOther
	default:
		// TODO(degradation): the purpose has no SPDX 3 name.
		return ""
	}
}

// externalRefTypeToSPDX3 returns the SPDX 3 external reference type naming a
// protobom external reference. Every value it returns is a member of the
// 3.0.1 ExternalRefType vocabulary.
func externalRefTypeToSPDX3(extRef *sbom.ExternalReference) string {
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
