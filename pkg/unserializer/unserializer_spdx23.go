package unserializer

import (
	"strings"
	"time"

	protospdx "github.com/bom-squad/protobom/pkg/formats/spdx"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var _ SPDX23Unserializer = &UnserializerSPDX23{}

type UnserializerSPDX23 struct{}

func (u *UnserializerSPDX23) Metadata(doc *spdx23.Document) (*sbom.Metadata, *sbom.NodeList, error) {
	md := &sbom.Metadata{
		Id:   string(doc.SPDXIdentifier),
		Name: doc.DocumentName,
	}

	// TODO(degradation): External document references
	// TODO(puerco) Top level elements
	if t := u.spdxDateToTime(doc.CreationInfo.Created); t != nil {
		md.Date = timestamppb.New(*t)
	}
	if doc.CreationInfo.Creators != nil {
		for _, c := range doc.CreationInfo.Creators {
			// TODO: We need to create a parser library in formats/spdx
			if c.CreatorType == "Tool" {
				// TODO: Split the version from the Tool string here.
				md.Tools = append(md.Tools, &sbom.Tool{Name: c.Creator})
				continue
			}
			a := &sbom.Person{Name: c.Creator}
			a.IsOrg = (c.CreatorType == protospdx.Organization)
			md.Authors = append(md.Authors, a)
		}
	}

	// TODO(degradation): SPDX LicenseVersion
	return md, nil, nil
}

func (u *UnserializerSPDX23) NodeList(doc *spdx23.Document) (*sbom.NodeList, error) {
	nl := &sbom.NodeList{}
	for _, p := range doc.Packages {
		nl.AddNode(u.PackageToNode(p))
	}

	for _, f := range doc.Files {
		nl.AddNode(u.FileToNode(f))
	}

	for _, r := range doc.Relationships {
		// The SPDX go library surfaces the JSON top-level elements as relationships:
		if r.RefA.ElementRefID == "DOCUMENT" && strings.EqualFold(r.Relationship, "DESCRIBES") {
			nl.RootElements = append(nl.RootElements, string(r.RefB.ElementRefID))
		} else {
			nl.AddEdge(u.relationshipToEdge(r))
		}
	}

	return nl, nil
}

// PackageToNode assigns the data from an SPDX package into a new Node
func (u *UnserializerSPDX23) PackageToNode(p *spdx23.Package) *sbom.Node {
	n := &sbom.Node{
		Id:              string(p.PackageSPDXIdentifier),
		Type:            sbom.Node_PACKAGE,
		Name:            p.PackageName,
		Version:         p.PackageVersion,
		FileName:        p.PackageFileName,
		UrlHome:         p.PackageHomePage,
		UrlDownload:     p.PackageDownloadLocation,
		LicenseComments: p.PackageLicenseComments,
		Copyright:       p.PackageCopyrightText,
		SourceInfo:      p.PackageSourceInfo,
		PrimaryPurpose:  p.PrimaryPackagePurpose,
		Comment:         p.PackageComment,
		Summary:         p.PackageSummary,
		Description:     p.PackageDescription,
		Attribution:     p.PackageAttributionTexts,
		Identifiers:     map[int32]string{},
	}

	// TODO(degradation) NOASSERTION
	if p.PackageLicenseConcluded != protospdx.NOASSERTION && p.PackageLicenseConcluded != "" {
		n.LicenseConcluded = p.PackageLicenseConcluded
	}

	if len(p.PackageChecksums) > 0 {
		n.Hashes = map[string]string{}
		for _, h := range p.PackageChecksums {
			n.Hashes[string(h.Algorithm)] = h.Value
		}
	}

	if len(p.PackageExternalReferences) > 0 {
		n.ExternalReferences = []*sbom.ExternalReference{}
		for _, r := range p.PackageExternalReferences {
			// If it is a software identifier, catch it and continue:
			idType := sbom.SoftwareIdentifierTypeFromSPDXExtRefType(r.RefType)
			if idType != sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
				n.Identifiers[int32(idType)] = r.Locator
				continue
			}

			// Else, it goes into the external references
			n.ExternalReferences = append(n.ExternalReferences, &sbom.ExternalReference{
				Url:     r.Locator,
				Type:    r.RefType,
				Comment: r.ExternalRefComment,
			})
		}
	}

	if t := u.spdxDateToTime(p.ValidUntilDate); t != nil {
		n.ValidUntilDate = timestamppb.New(*t)
	}
	if t := u.spdxDateToTime(p.ReleaseDate); t != nil {
		n.ReleaseDate = timestamppb.New(*t)
	}
	if t := u.spdxDateToTime(p.BuiltDate); t != nil {
		n.BuildDate = timestamppb.New(*t)
	}

	// Mmh there is a limitation here on the SPDX libraries. They will not
	// return the supplier and originator emails as a separate field. Perhaps
	// we should upstream a fix for that.
	if p.PackageSupplier != nil && p.PackageSupplier.Supplier != protospdx.NOASSERTION {
		n.Suppliers = []*sbom.Person{{Name: p.PackageSupplier.Supplier}}
		if p.PackageSupplier.SupplierType == protospdx.Organization {
			n.Suppliers[0].IsOrg = true
		}
	}

	if p.PackageOriginator != nil && p.PackageOriginator.Originator != protospdx.NOASSERTION && p.PackageOriginator.Originator != "" {
		n.Originators = []*sbom.Person{{Name: p.PackageOriginator.Originator}}
		if p.PackageOriginator.OriginatorType == protospdx.Organization {
			n.Originators[0].IsOrg = true
		}
	}

	return n
}

// FileToNode converts a file from SPDX into a protobom node
func (u *UnserializerSPDX23) FileToNode(f *spdx23.File) *sbom.Node {
	n := &sbom.Node{
		Id:               string(f.FileSPDXIdentifier),
		Type:             sbom.Node_FILE,
		Name:             f.FileName,
		Licenses:         f.LicenseInfoInFiles,
		LicenseConcluded: f.LicenseConcluded,
		LicenseComments:  f.LicenseComments,
		Copyright:        f.FileCopyrightText,
		Comment:          f.FileComment,
		Attribution:      []string{},
		Suppliers:        []*sbom.Person{},
		Originators:      []*sbom.Person{},
		FileTypes:        f.FileTypes,
	}

	if len(f.Checksums) > 0 {
		n.Hashes = map[string]string{}
		for _, h := range f.Checksums {
			n.Hashes[string(h.Algorithm)] = h.Value
		}
	}

	return n
}

// spdxDateToTime is a utility function that turns a date into a go time.Time
func (*UnserializerSPDX23) spdxDateToTime(date string) *time.Time {
	if date == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, date)
	if err != nil {
		logrus.Warnf("invalid time format in %s", date)
		return nil
	}
	return &t
}

// relationshipToEdge converts the SPDX relationship to a protobom Edge
func (*UnserializerSPDX23) relationshipToEdge(r *spdx23.Relationship) *sbom.Edge {
	// TODO(degradation) How to handle external documents?
	// TODO(degradation) How to handle NOASSERTION and NONE targets
	e := &sbom.Edge{
		Type: sbom.EdgeTypeFromSPDX2(r.Relationship),
		From: string(r.RefA.ElementRefID),
		To:   []string{string(r.RefB.ElementRefID)},
	}
	return e
}
