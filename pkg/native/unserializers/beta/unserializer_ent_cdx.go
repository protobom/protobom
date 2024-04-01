package beta

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sqlite "github.com/glebarez/go-sqlite"
	"github.com/sirupsen/logrus"

	"github.com/bom-squad/protobom/ent"
	"github.com/bom-squad/protobom/ent/documenttype"
	"github.com/bom-squad/protobom/ent/externalreference"
	"github.com/bom-squad/protobom/ent/hashesentry"
	"github.com/bom-squad/protobom/ent/identifiersentry"
	"github.com/bom-squad/protobom/ent/node"
	"github.com/bom-squad/protobom/ent/purpose"
	cdxformats "github.com/bom-squad/protobom/pkg/formats/cyclonedx"
	"github.com/bom-squad/protobom/pkg/native"
	"github.com/bom-squad/protobom/pkg/sbom"
)

// Enable SQLite foreign key support.
const dsnParams string = "?_pragma=foreign_keys(1)"

var (
	_      native.EntUnserializer = &EntCDX{}
	client *ent.Client            = ent.NewClient()
	ctx    context.Context        = context.Background()
)

type EntCDX struct {
	version      string
	encoding     string
	databaseFile string
}

// Overridden cdx types that implement EntUnserializer interface.
type (
	cdxComponents         []cdx.Component
	cdxComponentType      cdx.ComponentType
	cdxExternalReferences []cdx.ExternalReference
	cdxExtRefType         cdx.ExternalReferenceType
	cdxHashes             []cdx.Hash
	cdxHashAlg            cdx.HashAlgorithm
	cdxLicenseChoices     []cdx.LicenseChoice
	cdxLifecycles         []cdx.Lifecycle
	cdxLifecyclePhase     cdx.LifecyclePhase
	cdxOrgContacts        []cdx.OrganizationalContact
	cdxTools              cdx.ToolsChoice
)

func NewEntCDX(version, encoding, dbFile string) *EntCDX {
	if dbFile == "" {
		dbFile = ":memory:"
	}

	return &EntCDX{
		version:      version,
		encoding:     encoding,
		databaseFile: dbFile,
	}
}

// Unserialize converts a list of cdx.Component to their ent.Node representations
func (components *cdxComponents) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	if components == nil {
		return ent.Nodes{}
	}

	cc := 1
	entNodes := ent.Nodes{}

	for i := range *components {
		component := (*components)[i]

		nodeType := node.TypePACKAGE
		if component.Type == cdx.ComponentTypeFile {
			nodeType = node.TypeFILE
		}

		// Set applicable identifiers
		var identifiers ent.IdentifiersEntries
		if component.CPE != "" {
			t := identifiersentry.SoftwareIdentifierTypeCPE22
			if strings.HasPrefix(component.CPE, "cpe:2.3") {
				t = identifiersentry.SoftwareIdentifierTypeCPE23
			}

			identifiers = append(identifiers, client.IdentifiersEntry.Create().
				SetSoftwareIdentifierType(t).
				SetSoftwareIdentifierValue(component.CPE).
				SaveX(ctx))
		}

		if component.PackageURL != "" {
			identifiers = append(identifiers, client.IdentifiersEntry.Create().
				SetSoftwareIdentifierType(identifiersentry.SoftwareIdentifierTypePURL).
				SetSoftwareIdentifierValue(component.PackageURL).
				SaveX(ctx))
		}

		// Generate a new ID if none is set
		nodeID := component.BOMRef
		if nodeID == "" {
			nodeID = sbom.NewNodeIdentifier("auto", fmt.Sprintf("%09d", cc))
			cc++
		}

		entNodes = append(entNodes, client.Node.Create().
			SetID(nodeID).
			SetType(nodeType).
			SetName(component.Name).
			SetVersion(component.Version).
			SetCopyright(component.Copyright).
			SetDescription(component.Description).
			SetLicenses((*cdxLicenseChoices)(component.Licenses).Unserialize(r, nil, nil).([]string)).
			AddPrimaryPurpose(cdxComponentType(component.Type).Unserialize(r, nil, nil).(*ent.Purpose)).
			AddExternalReferences((*cdxExternalReferences)(component.ExternalReferences).
				Unserialize(r, nil, nil).(ent.ExternalReferences)...).
			AddHashes((*cdxHashes)(component.Hashes).Unserialize(r, nil, nil).(ent.HashesEntries)...).
			AddIdentifiers(identifiers...).
			SaveX(ctx))
	}

	return entNodes
}

// Unserialize converts a list of cdx.ExternalReference to their ent.ExternalReference representations
func (refs *cdxExternalReferences) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	if refs == nil {
		return ent.ExternalReferences{}
	}

	entRefs := ent.ExternalReferences{}

	for i := range *refs {
		ref := (*refs)[i]

		entRefs = append(entRefs, client.ExternalReference.Create().
			SetURL(ref.URL).
			SetComment(ref.Comment).
			AddHashes((*cdxHashes)(ref.Hashes).Unserialize(r, nil, nil).(ent.HashesEntries)...).
			SetType(cdxExtRefType(ref.Type).Unserialize(r, nil, nil).(externalreference.Type)).
			SaveX(ctx))
	}

	return entRefs
}

// Unserialize converts a list of cdx.Hash to their ent.HashesEntry representations
func (hashes *cdxHashes) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	if hashes == nil {
		return ent.HashesEntries{}
	}

	entHashes := ent.HashesEntries{}

	for i := range *hashes {
		hash := (*hashes)[i]
		alg := cdxHashAlg(hash.Algorithm).Unserialize(r, nil, nil)

		if alg == hashesentry.HashAlgorithmTypeUNKNOWN {
			continue
		}

		entHashes = append(entHashes, client.HashesEntry.Create().
			SetHashAlgorithmType(alg.(hashesentry.HashAlgorithmType)).
			SetHashData(hash.Value).
			SaveX(ctx))
	}

	return entHashes
}

// Unserialize converts a list of cdx.LicenseChoice to their ent representations
func (licenses *cdxLicenseChoices) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	var licenseStrings []string

	if licenses == nil {
		return licenseStrings
	}

	for i := range *licenses {
		license := (*licenses)[i]

		switch {
		case license.Expression != "":
			licenseStrings = append(licenseStrings, license.Expression)
		case license.License.ID != "":
			licenseStrings = append(licenseStrings, license.License.ID)
		case license.License.Name != "":
			licenseStrings = append(licenseStrings, license.License.Name)
		}
	}

	return licenseStrings
}

// Unserialize converts a list of cdx.Lifecycle to their ent.DocumentType representations
func (phases *cdxLifecycles) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	if phases == nil {
		return ent.DocumentTypes{}
	}

	entDocTypes := ent.DocumentTypes{}

	for i := range *phases {
		phase := (*phases)[i]

		entDocType := client.DocumentType.Create().
			SetName(phase.Name).
			SetDescription(phase.Description).
			SetType(cdxLifecyclePhase(phase.Phase).Unserialize(r, nil, nil).(documenttype.Type)).
			SaveX(ctx)

		entDocTypes = append(entDocTypes, entDocType)
	}

	return entDocTypes
}

// Unserialize converts a list of cdx.OrganizationalContact to their ent.Person representations
func (authors *cdxOrgContacts) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	entAuthors := ent.Persons{}

	for _, author := range *authors {
		entAuthors = append(entAuthors, client.Person.Create().
			SetName(author.Name).
			SetIsOrg(false).
			SetEmail(author.Email).
			SetPhone(author.Phone).
			SaveX(ctx))
	}

	return entAuthors
}

// Unserialize converts a cdx.ToolsChoice to its ent.Tool list representation
func (tools *cdxTools) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	entTools := ent.Tools{}

	if tools.Components != nil {
		for i := range *tools.Components {
			tool := (*tools.Components)[i]

			entTool := client.Tool.Create().
				SetName(tool.Name).
				SetVersion(tool.Version).
				SetVendor(tool.Publisher).
				SaveX(ctx)

			entTools = append(entTools, entTool)
		}
	} else if tools.Tools != nil {
		for i := range *tools.Tools {
			tool := (*tools.Tools)[i]

			entTool := client.Tool.Create().
				SetName(tool.Name).
				SetVersion(tool.Version).
				SetVendor(tool.Vendor).
				SaveX(ctx)

			entTools = append(entTools, entTool)
		}
	}

	return entTools
}

// Unserialize reads datq data from io.Reader r and parses it as a CycloneDX
// document. If successful returns a protobom Document loaded with the SBOM data.
func (entcdx *EntCDX) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	if !slices.Contains(sql.Drivers(), "sqlite3") {
		sqlite.RegisterAsSQLITE3()
	}

	client, err := ent.Open("sqlite3", entcdx.databaseFile+dsnParams)
	if err != nil {
		logrus.Fatalf("failed opening connection to sqlite: %v", err)
	}

	defer client.Close()

	// Run the auto migration tool.
	if err := client.Schema.Create(context.Background()); err != nil {
		logrus.Fatalf("failed creating schema resources: %v", err)
	}

	bom := new(cdx.BOM)

	encoding, err := cdxformats.ParseEncoding(entcdx.encoding)
	if err != nil {
		logrus.Fatalf("%v", err)
	}

	decoder := cdx.NewBOMDecoder(r, encoding)
	if err := decoder.Decode(bom); err != nil {
		logrus.Fatalf("decoding cyclonedx: %v", err)
	}

	var rootElements []string
	if bom.Metadata.Component != nil {
		rootElements = append(rootElements, bom.Metadata.Component.BOMRef)
	}

	nl := client.NodeList.Create().
		SetRootElements(rootElements).
		AddNodes((*cdxComponents)(bom.Components).Unserialize(r, nil, nil).(ent.Nodes)...).
		SaveX(ctx)

	ts := bom.Metadata.Timestamp
	if ts == "" {
		ts = time.Now().Format(time.RFC3339)
	}

	date, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		logrus.Fatalf("%v", err)
	}

	document := client.Document.Create().
		SetMetadata(client.Metadata.Create().
			SetID(bom.SerialNumber).
			SetVersion(fmt.Sprintf("%d", bom.Version)).
			SetDate(date).
			AddAuthors((*cdxOrgContacts)(bom.Metadata.Authors).Unserialize(r, nil, nil).([]*ent.Person)...).
			AddTools((*cdxTools)(bom.Metadata.Tools).Unserialize(r, nil, nil).([]*ent.Tool)...).
			AddDocumentTypes((*cdxLifecycles)(bom.Metadata.Lifecycles).Unserialize(r, nil, nil).([]*ent.DocumentType)...).
			SaveX(ctx),
		).
		SetNodeList(nl).
		SaveX(ctx)

	return document
}

// Unserialize converts a cdx.ComponentType to its ent purpose.PrimaryPurpose representation
func (cType cdxComponentType) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	switch cdx.ComponentType(cType) {
	case cdx.ComponentTypeApplication:
		return purpose.PrimaryPurposeAPPLICATION
	case cdx.ComponentTypeFramework:
		return purpose.PrimaryPurposeFRAMEWORK
	case cdx.ComponentTypeLibrary:
		return purpose.PrimaryPurposeLIBRARY
	case cdx.ComponentTypeContainer:
		return purpose.PrimaryPurposeCONTAINER
	case cdx.ComponentTypePlatform:
		return purpose.PrimaryPurposePLATFORM
	case cdx.ComponentTypeOS:
		return purpose.PrimaryPurposeOPERATING_SYSTEM
	case cdx.ComponentTypeDevice:
		return purpose.PrimaryPurposeDEVICE
	case cdx.ComponentTypeDeviceDriver:
		return purpose.PrimaryPurposeDEVICE_DRIVER
	case cdx.ComponentTypeFirmware:
		return purpose.PrimaryPurposeFIRMWARE
	case cdx.ComponentTypeFile:
		return purpose.PrimaryPurposeFILE
	case cdx.ComponentTypeMachineLearningModel:
		return purpose.PrimaryPurposeMACHINE_LEARNING_MODEL
	case cdx.ComponentTypeData:
		return purpose.PrimaryPurposeDATA
	default:
		return purpose.PrimaryPurposeUNKNOWN_PURPOSE
	}
}

// Unserialize converts a cdx.ExternalReferenceType to its ent externalreference.Type representation
func (refType cdxExtRefType) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	switch cdx.ExternalReferenceType(refType) {
	case cdx.ERTypeAttestation:
		return externalreference.TypeATTESTATION
	case cdx.ERTypeBOM:
		return externalreference.TypeBOM
	case cdx.ERTypeBuildMeta:
		return externalreference.TypeBUILD_META
	case cdx.ERTypeBuildSystem:
		return externalreference.TypeBUILD_SYSTEM
	case cdx.ERTypeCertificationReport:
		return externalreference.TypeCERTIFICATION_REPORT
	case cdx.ERTypeChat:
		return externalreference.TypeCHAT
	case cdx.ERTypeCodifiedInfrastructure:
		return externalreference.TypeCODIFIED_INFRASTRUCTURE
	case cdx.ERTypeComponentAnalysisReport:
		return externalreference.TypeCOMPONENT_ANALYSIS_REPORT
	case cdx.ExternalReferenceType("configuration"):
		return externalreference.TypeCONFIGURATION
	case cdx.ERTypeDistributionIntake:
		return externalreference.TypeDISTRIBUTION_INTAKE
	case cdx.ERTypeDistribution:
		return externalreference.TypeDOWNLOAD
	case cdx.ERTypeDocumentation:
		return externalreference.TypeDOCUMENTATION
	case cdx.ERTypeDynamicAnalysisReport:
		return externalreference.TypeDYNAMIC_ANALYSIS_REPORT
	case cdx.ExternalReferenceType("evidence"):
		return externalreference.TypeEVIDENCE
	case cdx.ExternalReferenceType("formulation"):
		return externalreference.TypeFORMULATION
	case cdx.ERTypeIssueTracker:
		return externalreference.TypeISSUE_TRACKER
	case cdx.ERTypeLicense:
		return externalreference.TypeLICENSE
	case cdx.ExternalReferenceType("log"):
		return externalreference.TypeLOG
	case cdx.ERTypeMailingList:
		return externalreference.TypeMAILING_LIST
	case cdx.ERTypeMaturityReport:
		return externalreference.TypeMATURITY_REPORT
	case cdx.ExternalReferenceType("model-card"):
		return externalreference.TypeMODEL_CARD
	case cdx.ERTypeOther:
		return externalreference.TypeOTHER
	case cdx.ExternalReferenceType("poam"):
		return externalreference.TypePOAM
	case cdx.ERTypeQualityMetrics:
		return externalreference.TypeQUALITY_METRICS
	case cdx.ERTypeReleaseNotes:
		return externalreference.TypeRELEASE_NOTES
	case cdx.ERTypeRiskAssessment:
		return externalreference.TypeRISK_ASSESSMENT
	case cdx.ERTypeRuntimeAnalysisReport:
		return externalreference.TypeRUNTIME_ANALYSIS_REPORT
	case cdx.ERTypeAdversaryModel:
		return externalreference.TypeSECURITY_ADVERSARY_MODEL
	case cdx.ERTypeAdvisories:
		return externalreference.TypeSECURITY_ADVISORY
	case cdx.ERTypeSecurityContact:
		return externalreference.TypeSECURITY_CONTACT
	case cdx.ERTypePentestReport:
		return externalreference.TypeSECURITY_PENTEST_REPORT
	case cdx.ERTypeThreatModel:
		return externalreference.TypeSECURITY_THREAT_MODEL
	case cdx.ERTypeSocial:
		return externalreference.TypeSOCIAL
	case cdx.ERTypeStaticAnalysisReport:
		return externalreference.TypeSTATIC_ANALYSIS_REPORT
	case cdx.ERTypeSupport:
		return externalreference.TypeSUPPORT
	case cdx.ERTypeVCS:
		return externalreference.TypeVCS
	case cdx.ERTypeVulnerabilityAssertion:
		return externalreference.TypeVULNERABILITY_ASSERTION
	case cdx.ERTypeExploitabilityStatement:
		return externalreference.TypeVULNERABILITY_EXPLOITABILITY_ASSESSMENT
	case cdx.ERTypeWebsite:
		return externalreference.TypeWEBSITE
	default:
		return externalreference.TypeOTHER
	}
}

// Unserialize converts a cdx.HashAlgorithm to its ent hashesentry.HashAlgorithmType representation
func (ha cdxHashAlg) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	switch cdx.HashAlgorithm(ha) {
	case cdx.HashAlgoMD5:
		return hashesentry.HashAlgorithmTypeMD5
	case cdx.HashAlgoSHA1:
		return hashesentry.HashAlgorithmTypeSHA1
	case cdx.HashAlgoSHA256:
		return hashesentry.HashAlgorithmTypeSHA256
	case cdx.HashAlgoSHA384:
		return hashesentry.HashAlgorithmTypeSHA384
	case cdx.HashAlgoSHA512:
		return hashesentry.HashAlgorithmTypeSHA512
	case cdx.HashAlgoSHA3_256:
		return hashesentry.HashAlgorithmTypeSHA3_256
	case cdx.HashAlgoSHA3_384:
		return hashesentry.HashAlgorithmTypeSHA3_384
	case cdx.HashAlgoSHA3_512:
		return hashesentry.HashAlgorithmTypeSHA3_512
	case cdx.HashAlgoBlake2b_256:
		return hashesentry.HashAlgorithmTypeBLAKE2B_256
	case cdx.HashAlgoBlake2b_384:
		return hashesentry.HashAlgorithmTypeBLAKE2B_384
	case cdx.HashAlgoBlake2b_512:
		return hashesentry.HashAlgorithmTypeBLAKE2B_512
	case cdx.HashAlgoBlake3:
		return hashesentry.HashAlgorithmTypeBLAKE3
	default:
		return hashesentry.HashAlgorithmTypeUNKNOWN
	}
}

// Unserialize converts a cdx.LifecyclePhase to its ent documenttype.Type representation
func (phase cdxLifecyclePhase) Unserialize(r io.Reader, _ *native.EntUnserializeOptions, _ any) any {
	switch cdx.LifecyclePhase(phase) {
	case cdx.LifecyclePhaseBuild:
		return documenttype.TypeBUILD
	case cdx.LifecyclePhaseDecommission:
		return documenttype.TypeDECOMISSION
	case cdx.LifecyclePhaseDesign:
		return documenttype.TypeDESIGN
	case cdx.LifecyclePhaseDiscovery:
		return documenttype.TypeDISCOVERY
	case cdx.LifecyclePhaseOperations:
		return documenttype.TypeDEPLOYED
	case cdx.LifecyclePhasePreBuild:
		return documenttype.TypeSOURCE
	case cdx.LifecyclePhasePostBuild:
		return documenttype.TypeANALYZED
	default:
		return documenttype.TypeOTHER
	}
}
