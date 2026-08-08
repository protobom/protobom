// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"errors"
	"fmt"
	"io"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/software"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Unserializer = &SPDX3{}

// spdx3SpecVersion is the version of the specification this reader
// understands. A document that says it is any other version is not read as
// though it were this one.
const spdx3SpecVersion = "3.0.1"

// errNoSpdxDocument is returned for a graph carrying no document element.
// SPDX 3 allows a bare element as the whole payload, but protobom reads
// bills of materials, and one is always carried by a document.
var errNoSpdxDocument = errors.New("no SpdxDocument element in the graph")

// SPDX3 reads SPDX 3.0.1 documents into protobom.
type SPDX3 struct{}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

// Unserialize reads an SPDX 3 document from a stream.
func (u *SPDX3) Unserialize(r io.Reader, _ *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	env, err := spdx3.NewParser().Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX 3 document: %w", err)
	}

	document, err := spdx3DocumentElement(env)
	if err != nil {
		return nil, err
	}

	if err := checkSPDX3Version(env, document); err != nil {
		return nil, err
	}

	rd := &spdx3Reader{
		env:      env,
		document: document,
		nodes:    map[string]*sbom.Node{},
	}

	bom := sbom.NewDocument()
	bom.Metadata.Id = document.GetSPDXID()
	bom.Metadata.Name = document.Name
	bom.Metadata.Comment = document.Comment

	// TODO(degradation): SPDX 3 has no version for the document itself, so
	// Metadata.Version has nothing to read.

	if ci := document.CreationInfo; ci != nil && ci.Created != nil {
		bom.Metadata.Date = timestamppb.New(ci.Created.Value)
	}

	rd.elements(bom.NodeList)
	rd.roots(bom.NodeList)

	// The relationships between the elements, the agents the document
	// credits and the licenses its elements are under are read in the steps
	// that follow this one.

	return bom, nil
}

// spdx3Reader carries what reading one document needs.
type spdx3Reader struct {
	env      *spdx3.Envelope
	document *core.SpdxDocument

	// nodes indexes the elements that became nodes by the identifier they
	// carry in the document, which is what its roots and relationships name
	// them by.
	nodes map[string]*sbom.Node
}

// elements reads the graph's software elements into nodes.
//
// Elements are selected by their concrete class and never by what they
// descend from. SPDX 3 puts Snippet under SoftwareArtifact and Vulnerability
// under Artifact, so a reader that asks what an element descends from ingests
// elements protobom has no node type for. Everything not matched here is left
// alone: collections are unwrapped rather than ingested, agents and licenses
// are consumed where they are referenced, and the rest has no home.
func (rd *spdx3Reader) elements(nl *sbom.NodeList) {
	for _, element := range rd.env.Graph {
		var node *sbom.Node
		switch e := element.(type) {
		case *software.Package:
			node = rd.pkg(e)
		case *software.File:
			node = rd.file(e)
		default:
			continue
		}

		// A document that names one element twice is not one to merge
		// silently: the first is kept and the second dropped.
		if _, seen := rd.nodes[node.Id]; seen {
			continue
		}
		rd.nodes[node.Id] = node
		nl.AddNode(node)
	}
}

// pkg reads a package element.
func (rd *spdx3Reader) pkg(p *software.Package) *sbom.Node {
	node := rd.softwareArtifact(&p.SoftwareArtifact)
	node.Type = sbom.Node_PACKAGE
	node.Version = p.PackageVersion
	node.UrlDownload = p.DownloadLocation
	node.UrlHome = p.HomePage
	node.SourceInfo = p.SourceInfo

	if p.PackageUrl != "" {
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = p.PackageUrl
	}

	// The package verification code is not read: it is derived from the
	// package's files, and protobom computes it when it writes a document
	// rather than carrying it. See spdx_verification_code.go.

	return node
}

// file reads a file element.
func (rd *spdx3Reader) file(f *software.File) *sbom.Node {
	node := rd.softwareArtifact(&f.SoftwareArtifact)
	node.Type = sbom.Node_FILE
	node.ContentType = f.ContentType
	node.FileKind = fileKindFromSPDX3(f.FileKind)
	return node
}

// softwareArtifact reads what the software profile adds to an artifact.
func (rd *spdx3Reader) softwareArtifact(a *software.SoftwareArtifact) *sbom.Node {
	node := rd.artifact(&a.Artifact)
	node.Copyright = a.CopyrightText
	node.Attribution = a.AttributionText
	node.PrimaryPurpose = purposesFromSPDX3(a.PrimaryPurpose, a.AdditionalPurpose)

	for _, id := range a.ContentIdentifier {
		// TODO(degradation): protobom has no identifier type for a swhid,
		// so only gitoids survive.
		if id.ContentIdentifierType == software.ContentIdentifierTypeGitoid {
			node.Identifiers[int32(sbom.SoftwareIdentifierType_GITOID)] = id.ContentIdentifierValue
		}
	}

	return node
}

// artifact reads the properties every element carries and those an artifact
// adds to them.
func (rd *spdx3Reader) artifact(a *core.Artifact) *sbom.Node {
	// The identifier is kept as the document states it. SPDX 3 identifies
	// elements with an IRI where protobom takes any string, and the IRIs a
	// document uses are its own business: they are urn:uuids as often as
	// they are paths under the document's namespace.
	node := &sbom.Node{
		Id:                 a.GetSPDXID(),
		Name:               a.Name,
		Summary:            a.Summary,
		Description:        a.Description,
		Comment:            a.Comment,
		Attribution:        []string{},
		Suppliers:          []*sbom.Person{},
		Originators:        []*sbom.Person{},
		ExternalReferences: []*sbom.ExternalReference{},
		FileTypes:          []string{},
		Identifiers:        map[int32]string{},
		Hashes:             map[int32]string{},
	}

	if a.BuiltTime != nil {
		node.BuildDate = timestamppb.New(a.BuiltTime.Value)
	}
	if a.ReleaseTime != nil {
		node.ReleaseDate = timestamppb.New(a.ReleaseTime.Value)
	}
	if a.ValidUntilTime != nil {
		node.ValidUntilDate = timestamppb.New(a.ValidUntilTime.Value)
	}

	// TODO: suppliedBy and originatedBy are agents, and are read with the
	// rest of them.

	for _, method := range a.VerifiedUsing {
		// Only a Hash says something protobom can hold. A package
		// verification code is derived data, and is recomputed on write.
		hash, ok := method.(*core.Hash)
		if !ok {
			continue
		}
		algo := sbom.HashAlgorithmFromSPDX3(string(hash.Algorithm))
		if algo == sbom.HashAlgorithm_UNKNOWN {
			// TODO(degradation): the algorithm has no protobom name.
			continue
		}
		node.Hashes[int32(algo)] = hash.HashValue
	}

	for _, id := range a.ExternalIdentifier {
		t := identifierTypeFromSPDX3(id.ExternalIdentifierType)
		if t == sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
			// TODO(degradation): seven of the eleven SPDX 3 identifier
			// types have no protobom equivalent.
			continue
		}
		node.Identifiers[int32(t)] = id.Identifier
	}

	for _, ref := range a.ExternalRef {
		// TODO(degradation): SPDX 3 lets a reference carry several
		// locators where protobom holds one URL, so any after the first
		// are lost.
		url := ""
		if len(ref.Locator) > 0 {
			url = ref.Locator[0]
		}
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:     url,
			Type:    externalRefTypeFromSPDX3(ref.ExternalRefType),
			Comment: ref.Comment,
		})
	}

	return node
}

// roots follows what the document says it is about down to the software it
// is about.
//
// A document names a bill of materials, and the bill of materials names the
// software. Reading the document's roots verbatim would make the collection
// itself the root, which protobom has no node for, and lose the real ones.
func (rd *spdx3Reader) roots(nl *sbom.NodeList) {
	seen := map[string]struct{}{}
	visited := map[string]struct{}{}

	var follow func(elements []core.ElementDescendant)
	follow = func(elements []core.ElementDescendant) {
		for _, element := range elements {
			id := element.GetSPDXID()

			if roots, isCollection := spdx3CollectionRoots(element); isCollection {
				// A collection naming itself, directly or around a longer
				// loop, is followed once.
				if _, been := visited[id]; been {
					continue
				}
				visited[id] = struct{}{}
				follow(roots)
				continue
			}

			if _, isNode := rd.nodes[id]; !isNode {
				continue
			}
			if _, already := seen[id]; already {
				continue
			}
			seen[id] = struct{}{}
			nl.RootElements = append(nl.RootElements, id)
		}
	}

	// TODO: a document may also say what it is about with a describes
	// relationship, which is read with the rest of them.
	follow(rd.document.RootElement)
}

// spdx3CollectionRoots returns the elements a collection names as its roots,
// and whether the element is a collection at all. The model gives collections
// no marker of their own, so they are matched by concrete class, which is
// what the elements themselves get for the same reason.
func spdx3CollectionRoots(element core.ElementDescendant) ([]core.ElementDescendant, bool) {
	switch c := element.(type) {
	case *core.SpdxDocument:
		return c.RootElement, true
	case *software.Sbom:
		return c.RootElement, true
	case *core.Bom:
		return c.RootElement, true
	case *core.Bundle:
		return c.RootElement, true
	case *core.ElementCollection:
		return c.RootElement, true
	default:
		return nil, false
	}
}

// spdx3DocumentElement returns the graph's document element, which is what
// says the document is a document rather than a loose collection of elements.
func spdx3DocumentElement(env *spdx3.Envelope) (*core.SpdxDocument, error) {
	for _, node := range env.Graph {
		if document, ok := node.(*core.SpdxDocument); ok {
			return document, nil
		}
	}
	return nil, errNoSpdxDocument
}

// checkSPDX3Version reads the version the document states and refuses to
// read one this reader does not understand, rather than reading it as though
// it were 3.0.1 and quietly making up the difference.
//
// The version is stated in the creation information, which every element
// carries; the context URL pins it as well, and the two are checked against
// each other, since a document that says two different things about its own
// version is not one to guess about.
func checkSPDX3Version(env *spdx3.Envelope, document *core.SpdxDocument) error {
	stated := ""
	if document.CreationInfo != nil {
		stated = document.CreationInfo.SpecVersion
	}
	if stated == "" {
		return errors.New("document states no specVersion")
	}
	if stated != spdx3SpecVersion {
		return fmt.Errorf(
			"unsupported SPDX version %q, this reader understands %s",
			stated, spdx3SpecVersion,
		)
	}

	// An absent or unrecognized context is not fatal: the version the
	// document states about itself is what governs.
	if context := env.Context.Version(); context != "" && context != stated {
		return fmt.Errorf(
			"document states version %s but its @context is for %s",
			stated, context,
		)
	}
	return nil
}
