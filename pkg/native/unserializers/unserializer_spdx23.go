package unserializers

import (
	"fmt"
	"io"
	"strings"
	"time"

	protospdx "github.com/bom-squad/protobom/pkg/formats/spdx"
	"github.com/bom-squad/protobom/pkg/native"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	spdxjson "github.com/spdx/tools-golang/json"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var _ native.Unserializer = &SPDX23{}

type SPDX23 struct{}

func NewSPDX23() *SPDX23 {
	return &SPDX23{}
}

// ParseStream reads an io.Reader to parse an SPDX 2.3 document from it
func (u *SPDX23) Unserialize(r io.Reader, _ *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	spdxDoc, err := spdxjson.Read(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX json: %w", err)
	}

	bom := sbom.NewDocument()
	bom.Metadata.Id = string(spdxDoc.SPDXIdentifier)
	bom.Metadata.Name = spdxDoc.DocumentName

	// TODO(degradation): External document references

	// TODO(puerco) Top level elements
	if spdxDoc.CreationInfo != nil {
		if t := u.spdxDateToTime(spdxDoc.CreationInfo.Created); t != nil {
			bom.Metadata.Date = timestamppb.New(*t)
		}
		if spdxDoc.CreationInfo.Creators != nil {
			for _, c := range spdxDoc.CreationInfo.Creators {
				// TODO: We need to create a parser library in formats/spdx
				if c.CreatorType == "Tool" {
					// TODO: Split the version from the Tool string here.
					bom.Metadata.Tools = append(bom.Metadata.Tools, &sbom.Tool{Name: c.Creator})
					continue
				}
				a := &sbom.Person{Name: c.Creator}
				a.IsOrg = (c.CreatorType == protospdx.Organization)
				bom.Metadata.Authors = append(bom.Metadata.Authors, a)
			}
		}
	}

	// TODO(degradation): SPDX LicenseVersion

	for _, p := range spdxDoc.Packages {
		bom.NodeList.AddNode(u.packageToNode(p))
	}

	for _, f := range spdxDoc.Files {
		bom.NodeList.AddNode(u.fileToNode(f))
	}

	for _, r := range spdxDoc.Relationships {
		// The SPDX go library surfaces the JSON top-level elements as relationships:
		if r.RefA.ElementRefID == "DOCUMENT" && strings.EqualFold(r.Relationship, "DESCRIBES") {
			bom.NodeList.RootElements = append(bom.NodeList.RootElements, string(r.RefB.ElementRefID))
		} else {
			bom.NodeList.AddEdge(u.relationshipToEdge(r))
		}
	}

	return bom, nil
}

// packageToNode assigns the data from an SPDX package into a new Node
func (u *SPDX23) packageToNode(p *spdx23.Package) *sbom.Node {
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
		Comment:         p.PackageComment,
		Summary:         p.PackageSummary,
		Description:     p.PackageDescription,
		Attribution:     p.PackageAttributionTexts,
		Identifiers:     map[int32]string{},
	}

	purpose_value, ok := sbom.Purpose_value[string(p.PrimaryPackagePurpose)]
	if !ok {
		// Handle the error or set a default value
		//node.PrimaryPurpose = sbom.Purpose_UNKNOWN_PURPOSE
	} else {
		n.PrimaryPurpose = sbom.Purpose(purpose_value)
	}

	// TODO(degradation) NOASSERTION
	if p.PackageLicenseConcluded != protospdx.NOASSERTION && p.PackageLicenseConcluded != "" {
		n.LicenseConcluded = p.PackageLicenseConcluded
	}

	if len(p.PackageChecksums) > 0 {
		n.Hashes = map[int32]string{}
		for _, h := range p.PackageChecksums {
			algo := sbom.HashAlgorithmFromSPDX(h.Algorithm)
			if algo == sbom.HashAlgorithm_UNKNOWN {
				// TODO(degradation): Invalid algorithm in SBOM
				continue
			}
			n.Hashes[int32(algo)] = h.Value
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

// spdxDateToTime is a utility function that turns a date into a go time.Time
func (*SPDX23) spdxDateToTime(date string) *time.Time {
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

// fileToNode converts a file from SPDX into a protobom node
func (u *SPDX23) fileToNode(f *spdx23.File) *sbom.Node {
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
		n.Hashes = map[int32]string{}
		for _, h := range f.Checksums {
			algo := sbom.HashAlgorithmFromSPDX(h.Algorithm)
			if algo == sbom.HashAlgorithm_UNKNOWN {
				// TODO(degradation): Invalid SPDX algorith in SBOM. Error? Warning?
				continue
			}
			n.Hashes[int32(algo)] = h.Value
		}
	}

	return n
}

// relationshipToEdge converts the SPDX relationship to a protobom Edge
func (*SPDX23) relationshipToEdge(r *spdx23.Relationship) *sbom.Edge {
	// TODO(degradation) How to handle external documents?
	// TODO(degradation) How to handle NOASSERTION and NONE targets
	e := &sbom.Edge{
		Type: sbom.EdgeTypeFromSPDX2(r.Relationship),
		From: string(r.RefA.ElementRefID),
		To:   []string{string(r.RefB.ElementRefID)},
	}
	return e
}
