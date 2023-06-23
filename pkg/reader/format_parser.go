// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/onesbom/onesbom/pkg/formats/spdx"
	spdx23 "github.com/onesbom/onesbom/pkg/formats/spdx/v23"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type FormatParser interface {
	Parse(*options.Options, io.Reader) (*sbom.Document, error)
}

type FormatParserSPDX23 struct{}

type FormatParserCDX14 struct{}

func (gfp *FormatParserSPDX23) Parse(opts *options.Options, r io.Reader) (*sbom.Document, error) {
	spdxDoc := &spdx23.Document{}
	dc := json.NewDecoder(r)
	if err := dc.Decode(spdxDoc); err != nil {
		return nil, fmt.Errorf("decoding SPDX 2.3 document: %w", err)
	}

	bom := sbom.NewDocument()
	bom.Metadata.Id = spdxDoc.ID
	bom.Metadata.Name = spdxDoc.Name

	// Add the top level components
	bom.NodeList.RootElements = spdxDoc.DocumentDescribes

	// Assign the document metadata

	// Range the packages and add them to the doc
	for i := range spdxDoc.Packages {
		p, err := package23ToNode(&spdxDoc.Packages[i])
		if err != nil {
			return nil, fmt.Errorf("rendering node from spdx package: %w", err)
		}

		bom.NodeList.Nodes = append(bom.NodeList.Nodes, p)
	}

	for i := range spdxDoc.Files {
		f, err := file23ToNode(&spdxDoc.Files[i])
		if err != nil {
			return nil, fmt.Errorf("creating node from spdx file: %w", nil)
		}

		bom.NodeList.Nodes = append(bom.NodeList.Nodes, f)
	}

	for i := range spdxDoc.Relationships {
		e, err := relationship23ToEdge(&spdxDoc.Relationships[i])
		if err != nil {
			return nil, fmt.Errorf("")
		}
		bom.NodeList.Edges = append(bom.NodeList.Edges, e)
	}

	return bom, nil
}

func file23ToNode(spdxFile *spdx23.File) (*sbom.Node, error) {
	f := &sbom.Node{
		Id:                 strings.TrimPrefix(spdxFile.ID, spdx23.IDPrefix),
		Type:               1,
		Name:               spdxFile.Name,
		Licenses:           []string{},
		LicenseComments:    spdxFile.LicenseComments,
		Copyright:          spdxFile.CopyrightText,
		Comment:            spdxFile.Comment,
		Description:        spdxFile.Description,
		Suppliers:          []*sbom.Person{},
		Originators:        []*sbom.Person{},
		ReleaseDate:        &timestamppb.Timestamp{},
		BuildDate:          &timestamppb.Timestamp{},
		ValidUntilDate:     &timestamppb.Timestamp{},
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        []*sbom.Identifier{},
		FileTypes:          spdxFile.FileTypes,
	}

	f.Hashes = map[string]string{}
	for _, cs := range spdxFile.Checksums {
		f.Hashes[cs.Algorithm] = cs.Value
	}

	if spdxFile.Attribution != nil {
		f.Attribution = *spdxFile.Attribution
	}

	if spdxFile.LicenseConcluded != spdx.NOASSERTION && spdxFile.LicenseConcluded != "" {
		f.LicenseConcluded = spdxFile.LicenseConcluded
	}

	// License data found in files
	if spdxFile.LicenseInfoInFile != nil {
		f.Licenses = spdxFile.LicenseInfoInFile
	}

	return f, nil
}

func package23ToNode(spdxPackage *spdx23.Package) (*sbom.Node, error) {
	p := &sbom.Node{
		Type:               0,
		Name:               spdxPackage.Name,
		Version:            spdxPackage.Version,
		FileName:           spdxPackage.Filename,
		Copyright:          spdxPackage.CopyrightText,
		SourceInfo:         spdxPackage.SourceInfo,
		PrimaryPurpose:     spdxPackage.PrimaryPurpose,
		Comment:            spdxPackage.Comment,
		Description:        spdxPackage.Description,
		Attribution:        []string{},
		Suppliers:          []*sbom.Person{}, // TODO
		Originators:        []*sbom.Person{}, // TODO
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        []*sbom.Identifier{},
	}
	p.Id = strings.TrimPrefix(spdxPackage.ID, spdx23.IDPrefix)

	if spdxPackage.DownloadLocation != spdx.NOASSERTION {
		p.UrlDownload = spdxPackage.DownloadLocation
	}

	if spdxPackage.HomePage != spdx.NOASSERTION {
		p.UrlHome = spdxPackage.HomePage
	}

	if spdxPackage.Summary != spdx.NOASSERTION {
		p.Summary = spdxPackage.Summary
	}

	if spdxPackage.CopyrightText != spdx.NOASSERTION {
		p.Copyright = spdxPackage.CopyrightText
	}

	p.Hashes = map[string]string{}
	for _, cs := range spdxPackage.Checksums {
		p.Hashes[cs.Algorithm] = cs.Value
	}

	if spdxPackage.ExternalRefs != nil {
		p.Identifiers = []*sbom.Identifier{}
		for _, extid := range spdxPackage.ExternalRefs {
			p.Identifiers = append(p.Identifiers, &sbom.Identifier{
				Type:  extid.Type,
				Value: extid.Locator,
			})
		}
	}

	if spdxPackage.Supplier != "" {
		p.Suppliers = []*sbom.Person{}
		actorType, actorName, actorEmail := spdx.ParseActorString(spdxPackage.Supplier)
		if actorType != "" {
			p.Suppliers[0] = &sbom.Person{
				Name:  actorName,
				Email: actorEmail,
				IsOrg: (actorType == "org"),
			}
		}
	}

	if spdxPackage.Originator != "" {
		p.Suppliers = []*sbom.Person{}
		actorType, actorName, actorEmail := spdx.ParseActorString(spdxPackage.Originator)
		if actorType != "" {
			p.Originators[0] = &sbom.Person{
				Name:  actorName,
				Email: actorEmail,
				IsOrg: (actorType == "org"),
			}
		}
	}

	// License data
	if spdxPackage.LicenseDeclared != spdx.NOASSERTION && spdxPackage.LicenseDeclared != "" {
		p.Licenses = []string{spdxPackage.LicenseDeclared}
	}

	if spdxPackage.LicenseConcluded != spdx.NOASSERTION && spdxPackage.LicenseConcluded != "" {
		p.LicenseConcluded = spdxPackage.LicenseConcluded
	}

	if spdxPackage.ReleaseDate != nil {
		p.ReleaseDate = timestamppb.New(*spdxPackage.ReleaseDate)
	}

	if spdxPackage.BuildDate != nil {
		p.BuildDate = timestamppb.New(*spdxPackage.BuildDate)
	}

	if spdxPackage.ValidUntilDate != nil {
		p.ValidUntilDate = timestamppb.New(*spdxPackage.ValidUntilDate)
	}
	return p, nil
}

func relationship23ToEdge(r *spdx23.Relationship) (*sbom.Edge, error) {
	return &sbom.Edge{
		Type: sbom.EdgeTypeFromSPDX(r.Type),
		From: strings.TrimPrefix(r.Element, spdx23.IDPrefix),
		To:   []string{strings.TrimPrefix(r.Related, spdx23.IDPrefix)},
	}, nil
}
