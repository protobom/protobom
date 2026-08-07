// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/base"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/simplelicensing"
	"github.com/carabiner-dev/spdx3/profiles/software"
	spdx3types "github.com/carabiner-dev/spdx3/types"
	"sigs.k8s.io/release-utils/version"

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
type SPDX3 struct{}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

type SPDX3Options struct {
	// GenerateDocumentID causes the serializer to generate a document
	// identifier when the protobom has none.
	GenerateDocumentID bool
}

var DefaultSPDX3Options = SPDX3Options{
	GenerateDocumentID: true,
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

	namespace, err := spdxNamespaceFromProtobomID(SPDX23Options{
		GenerateDocumentID: opts.GenerateDocumentID,
	}, bom.Metadata.Id)
	if err != nil {
		return nil, fmt.Errorf("serializing SPDX namespace: %w", err)
	}

	env := spdx3.NewEnvelope()
	t := &spdx3Translator{namespace: namespace, env: env, nodeList: bom.NodeList}

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
		t.licenses(node, element)
	}

	// The relationships between them.
	for _, edge := range bom.NodeList.Edges {
		t.edge(edge)
	}

	// And the document that holds it all, naming what it is about.
	document := core.NewSpdxDocument(namespace)
	document.Name = bom.Metadata.Name
	document.Comment = bom.Metadata.Comment
	document.ProfileConformance = []core.ProfileIdentifierType{
		core.ProfileIdentifierTypeCore,
		core.ProfileIdentifierTypeSoftware,
		core.ProfileIdentifierTypeSimpleLicensing,
	}
	for _, id := range bom.NodeList.RootElements {
		document.AddRootElement(spdx3types.NodeRef{ID: t.elementID(id)})
	}
	for _, node := range env.Graph {
		if _, isElement := node.(core.ElementDescendant); isElement {
			document.AddElement(spdx3types.NodeRef{ID: node.GetSPDXID()})
		}
	}
	env.Graph.AddNode(document)

	// Said once, and shared by every element that has none of its own.
	env.Graph.SetCreationInfo(creation)

	return env, nil
}

// spdx3Translator carries what converting one document needs.
type spdx3Translator struct {
	namespace string
	env       *spdx3.Envelope
	nodeList  *sbom.NodeList
	counter   int
}

// elementID returns an identifier for an element. SPDX 3 identifies elements
// with a URI, so an identifier that is not one is taken to name an element of
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

	// Record protobom itself, as the SPDX 2.3 serializer does.
	self := core.NewTool(
		t.newID("tool"),
		fmt.Sprintf("protobom-%s", version.GetVersionInfo().GitVersion),
	)
	t.env.Graph.AddNode(self)
	creation.CreatedUsing = append(creation.CreatedUsing, self)

	for _, tool := range md.Tools {
		name := tool.Name
		if tool.Version != "" {
			name = fmt.Sprintf("%s-%s", tool.Name, tool.Version)
		}
		// TODO(degradation): a tool's vendor has nowhere to go in SPDX 3.
		element := core.NewTool(t.newID("tool"), name)
		t.env.Graph.AddNode(element)
		creation.CreatedUsing = append(creation.CreatedUsing, element)
	}

	// An SPDX 3 document states who created it, so credit protobom when the
	// protobom names nobody.
	if len(creation.CreatedBy) == 0 {
		creation.CreatedBy = append(creation.CreatedBy, spdx3types.NodeRef{ID: core.SpdxOrganizationIRI})
	}

	return creation
}

// agent converts a protobom person to the SPDX 3 agent modelling them.
func (t *spdx3Translator) agent(person *sbom.Person) core.AgentDescendant {
	id := t.newID("agent")
	var node *core.Node
	var agent core.AgentDescendant

	if person.IsOrg {
		organization := core.NewOrganization(id, person.Name)
		node, agent = &organization.Node, organization
	} else {
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
	f.PrimaryPurpose, f.AdditionalPurpose = purposesToSPDX3(n.PrimaryPurpose)

	// TODO(degradation): a node's SPDX 2 file types have no home in SPDX 3,
	// whose fileKind only tells a file from a directory.

	return f
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

	for algo, value := range n.Hashes {
		name := sbom.HashAlgorithm(algo).ToSPDX3()
		if name == "" {
			// TODO(degradation): the algorithm has no SPDX 3 name.
			continue
		}
		a.VerifiedUsing = append(a.VerifiedUsing, core.NewHash(core.HashAlgorithm(name), value))
	}

	for idType, value := range n.Identifiers {
		name := identifierTypeToSPDX3(sbom.SoftwareIdentifierType(idType))
		if name == "" {
			continue
		}
		a.ExternalIdentifier = append(a.ExternalIdentifier, core.ExternalIdentifier{
			Type:                   spdx3ExternalIdentifier,
			ExternalIdentifierType: name,
			Identifier:             value,
		})
	}

	for _, ref := range n.ExternalReferences {
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

// licenses states what a node is licensed under, which SPDX 3 says with a
// relationship to a license rather than with a field.
func (t *spdx3Translator) licenses(n *sbom.Node, element core.ElementDescendant) {
	add := func(expression string, relType core.RelationshipType) {
		if expression == "" {
			return
		}
		license := &simplelicensing.LicenseExpression{
			AnyLicenseInfo: simplelicensing.AnyLicenseInfo{Element: core.Element{Node: core.Node{
				PreNode: base.PreNode{
					SPDXID: t.newID("license"),
					Type:   spdx3LicenseExpression,
				},
			}}},
			LicenseExpression: expression,
		}
		t.env.Graph.AddNode(license)
		t.env.Graph.Relate(t.newID("relationship"), element, relType, license)
	}

	add(n.LicenseConcluded, core.RelationshipTypeHasConcludedLicense)

	// TODO(degradation): protobom carries a list of declared licenses, which
	// SPDX 3 states as one expression; they are joined with AND.
	if len(n.Licenses) > 0 {
		add(strings.Join(n.Licenses, " AND "), core.RelationshipTypeHasDeclaredLicense)
	}

	// TODO(degradation): a node's license comments have nowhere to go.
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
// primary and the rest, which it calls additional.
func purposesToSPDX3(purposes []sbom.Purpose) (primary software.SoftwarePurpose, additional []software.SoftwarePurpose) {
	names := []software.SoftwarePurpose{}
	for _, p := range purposes {
		if name := purposeToSPDX3(p); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	return names[0], names[1:]
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
