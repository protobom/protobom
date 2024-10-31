package unserializers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var _ native.Unserializer = &SPDX23{}

type SPDX23 struct{}

func NewSPDX23() *SPDX23 {
	return &SPDX23{}
}

// buildDocumentIdentifier builds the protobom identifier from
// the SPDX information.
func buildDocumentIdentifier(doc *spdx23.Document) string {
	// The namespace isentifies the spdx document uniquely
	if doc.DocumentNamespace != "" {
		return fmt.Sprintf("%s#%s", doc.DocumentNamespace, doc.SPDXIdentifier)
	}

	// If we don't have a namespace it is an invalid SPDX doc, but
	// protobom needs one so let's generate an URI
	return fmt.Sprintf(
		"%s/protobom-%s#%s", "https://spdx.org/spdxdocs",
		uuid.NewString(), doc.SPDXIdentifier,
	)
}

// ParseStream reads an io.Reader to parse an SPDX 2.3 document from it
func (u *SPDX23) Unserialize(r io.Reader, opts *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	spdxDoc, err := spdxjson.Read(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX json: %w", err)
	}

	bom := sbom.NewDocument()
	bom.Metadata.Id = buildDocumentIdentifier(spdxDoc)
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
		bom.NodeList.AddNode(u.packageToNode(opts, p))
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
func (u *SPDX23) packageToNode(opts *native.UnserializeOptions, p *spdx23.Package) *sbom.Node {
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

	// SPDX 2.3 PrimaryPackagePurpose types: APPLICATION | FRAMEWORK | LIBRARY | CONTAINER | OPERATING-SYSTEM | DEVICE | FIRMWARE | SOURCE | ARCHIVE | FILE | INSTALL | OTHER
	switch p.PrimaryPackagePurpose {
	case "APPLICATION":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
	case "FRAMEWORK":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FRAMEWORK}
	case "LIBRARY":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_LIBRARY}
	case "CONTAINER":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_CONTAINER}
	case "OPERATING-SYSTEM":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_OPERATING_SYSTEM}
	case "DEVICE":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_DEVICE}
	case "FIRMWARE":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FIRMWARE}
	case "SOURCE":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_SOURCE}
	case "ARCHIVE":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_ARCHIVE}
	case "FILE":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FILE}
	case "INSTALL":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_INSTALL}
	case "OTHER":
		n.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_OTHER}
	case "":
	default:
		// TODO(degradation): unknown PrimaryPackagePurpose not preserved in protobom struct
	}

	// TODO(degradation) NOASSERTION
	if p.PackageLicenseConcluded != protospdx.NOASSERTION && p.PackageLicenseConcluded != "" {
		n.LicenseConcluded = p.PackageLicenseConcluded
	}

	// TODO(degradation) NOASSERTION
	if p.PackageLicenseDeclared != protospdx.NOASSERTION && p.PackageLicenseDeclared != "" {
		n.Licenses = []string{p.PackageLicenseDeclared}
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
			extRefType, isIdentifier, err := u.extRefToProtobomEnum(r)
			if err != nil {
				// TODO(degradation): Invalid external reference
				continue
			}

			if !isIdentifier {
				// Else, it goes into the external references
				n.ExternalReferences = append(n.ExternalReferences, &sbom.ExternalReference{
					Url:     r.Locator,
					Type:    extRefType,
					Comment: r.ExternalRefComment,
				})
				continue
			}

			// If it is a software identifier, catch it and continue:
			idType := u.extRefTypeToIdentifierType(r.RefType)
			if idType != sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
				n.Identifiers[int32(idType)] = r.Locator
				continue
			}
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

	// If the hack to read properties is enabled, unmarshall any properties
	// created by protobom:
	if opts.IsModEnabled(mod.SPDX_READ_ANNOTATIONS_TO_PROPERTIES) {
		for i := range p.Annotations {
			if p.Annotations[i].Annotator.AnnotatorType != "Tool" ||
				p.Annotations[i].Annotator.Annotator != "protobom - v1.0.0" {
				continue
			}

			property := &sbom.Property{}
			if err := json.Unmarshal([]byte(p.Annotations[i].AnnotationComment), property); err != nil {
				continue
			}
			n.Properties = append(n.Properties, property)
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

// extRefToProtobomEnum converts the SPDX external reference to the corresponding
// enumerated type. If the type is a software identifier, the function will return
// -1 and the isIdentifier will be set to true.
func (*SPDX23) extRefToProtobomEnum(extref *spdx.PackageExternalReference) (sbom.ExternalReference_ExternalReferenceType, bool, error) {
	switch extref.Category {
	case spdx.CategoryPackageManager:
		switch extref.RefType {
		case spdx.PackageManagerBower:
			return sbom.ExternalReference_BOWER, false, nil
		case spdx.PackageManagerMavenCentral:
			return sbom.ExternalReference_MAVEN_CENTRAL, false, nil
		case spdx.PackageManagerNpm:
			return sbom.ExternalReference_NPM, false, nil
		case spdx.PackageManagerNuGet:
			return sbom.ExternalReference_NUGET, false, nil
		case spdx.PackageManagerPURL:
			// Software identifiers will be captured and set into the software id field
			return -1, true, nil
		default:
			return -1, false, errors.New("invalid package manager type")
		}
	case spdx.CategorySecurity:
		switch extref.RefType {
		case spdx.SecurityAdvisory:
			return sbom.ExternalReference_SECURITY_ADVISORY, false, nil
		case spdx.SecurityFix:
			return sbom.ExternalReference_SECURITY_FIX, false, nil
		case spdx.SecuritySwid:
			return sbom.ExternalReference_SECURITY_SWID, false, nil
		case spdx.SecurityUrl:
			return sbom.ExternalReference_SECURITY_OTHER, false, nil
		case spdx.SecurityCPE22Type, spdx.SecurityCPE23Type:
			// Software identifiers will be captured and set into the software id field
			return -1, true, nil
		default:
			return -1, false, errors.New("invalid security type")
		}
	case spdx.CategoryPersistentId:
		// Persistent IDs are software IDs so we don't read them into
		// external references but still we check they are valid
		switch extref.RefType {
		case spdx.TypePersistentIdGitoid, spdx.TypePersistentIdSwh:
			return -1, true, nil
		default:
			return -1, false, errors.New("invalid persistent id")
		}
	default:
		return sbom.ExternalReference_OTHER, false, nil
	}
}

// extRefTypeToIdentifierType converts an SPDX software identifier type
// to the corresponding type
func (*SPDX23) extRefTypeToIdentifierType(spdxType string) sbom.SoftwareIdentifierType {
	switch spdxType {
	case spdx.PackageManagerPURL:
		return sbom.SoftwareIdentifierType_PURL
	case spdx.SecurityCPE22Type:
		return sbom.SoftwareIdentifierType_CPE22
	case spdx.SecurityCPE23Type:
		return sbom.SoftwareIdentifierType_CPE23
	case spdx.TypePersistentIdGitoid:
		return sbom.SoftwareIdentifierType_GITOID
	default:
		return sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE
	}
}
