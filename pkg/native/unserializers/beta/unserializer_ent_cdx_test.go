package beta

import (
	"bytes"
	"database/sql"
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sqlite "github.com/glebarez/go-sqlite"
	"github.com/stretchr/testify/suite"

	"github.com/bom-squad/protobom/ent"
	"github.com/bom-squad/protobom/ent/documenttype"
	"github.com/bom-squad/protobom/ent/externalreference"
	"github.com/bom-squad/protobom/ent/hashesentry"
	"github.com/bom-squad/protobom/ent/purpose"
)

type entCDXsuite struct {
	suite.Suite
	client *ent.Client
}

func (ecs *entCDXsuite) BeforeTest(suiteName, testName string) {
	if !slices.Contains(sql.Drivers(), "sqlite3") {
		sqlite.RegisterAsSQLITE3()
	}

	client, err := ent.Open("sqlite3", ":memory:"+dsnParams)
	if err != nil {
		ecs.T().Fatalf("%v", err)
	}

	ecs.client = client
}

func (ecs *entCDXsuite) AfterTest(suiteName, testName string) {
	ecs.client.Close()
}

func (s *entCDXsuite) TestCDXPhaseToSBOMType() {
	r := bytes.NewReader([]byte(""))

	for phase, dtype := range map[cdx.LifecyclePhase]documenttype.Type{
		cdx.LifecyclePhaseBuild:        documenttype.TypeBUILD,
		cdx.LifecyclePhaseDecommission: documenttype.TypeDECOMISSION,
		cdx.LifecyclePhaseDesign:       documenttype.TypeDESIGN,
		cdx.LifecyclePhaseDiscovery:    documenttype.TypeDISCOVERY,
		cdx.LifecyclePhaseOperations:   documenttype.TypeDEPLOYED,
		cdx.LifecyclePhasePostBuild:    documenttype.TypeANALYZED,
		cdx.LifecyclePhasePreBuild:     documenttype.TypeSOURCE,
		cdx.LifecyclePhase("invalid"):  documenttype.TypeOTHER,
	} {
		res := cdxLifecyclePhase(phase).Unserialize(r, nil, nil)
		s.Require().Equal(dtype, res)
	}
}

func (s *entCDXsuite) TestComponentTypeToPurpose() {
	r := bytes.NewReader([]byte(""))

	for compType, purpose := range map[cdx.ComponentType]purpose.PrimaryPurpose{
		cdx.ComponentTypeApplication:          purpose.PrimaryPurposeAPPLICATION,
		cdx.ComponentTypeFramework:            purpose.PrimaryPurposeFRAMEWORK,
		cdx.ComponentTypeLibrary:              purpose.PrimaryPurposeLIBRARY,
		cdx.ComponentTypeContainer:            purpose.PrimaryPurposeCONTAINER,
		cdx.ComponentTypePlatform:             purpose.PrimaryPurposePLATFORM,
		cdx.ComponentTypeOS:                   purpose.PrimaryPurposeOPERATING_SYSTEM,
		cdx.ComponentTypeDevice:               purpose.PrimaryPurposeDEVICE,
		cdx.ComponentTypeDeviceDriver:         purpose.PrimaryPurposeDEVICE_DRIVER,
		cdx.ComponentTypeFirmware:             purpose.PrimaryPurposeFIRMWARE,
		cdx.ComponentTypeFile:                 purpose.PrimaryPurposeFILE,
		cdx.ComponentTypeMachineLearningModel: purpose.PrimaryPurposeMACHINE_LEARNING_MODEL,
		cdx.ComponentTypeData:                 purpose.PrimaryPurposeDATA,
		cdx.ComponentType("invalid"):          purpose.PrimaryPurposeUNKNOWN_PURPOSE,
	} {
		res := cdxComponentType(compType).Unserialize(r, nil, nil)
		s.Require().Equal(purpose, res)
	}
}

func (s *entCDXsuite) TestCDXHashAlgToProtobomAlgo() {
	r := bytes.NewReader([]byte(""))

	for c, p := range map[cdx.HashAlgorithm]hashesentry.HashAlgorithmType{
		cdx.HashAlgoMD5:              hashesentry.HashAlgorithmTypeMD5,
		cdx.HashAlgoSHA1:             hashesentry.HashAlgorithmTypeSHA1,
		cdx.HashAlgoSHA256:           hashesentry.HashAlgorithmTypeSHA256,
		cdx.HashAlgoSHA384:           hashesentry.HashAlgorithmTypeSHA384,
		cdx.HashAlgoSHA512:           hashesentry.HashAlgorithmTypeSHA512,
		cdx.HashAlgoSHA3_256:         hashesentry.HashAlgorithmTypeSHA3_256,
		cdx.HashAlgoSHA3_384:         hashesentry.HashAlgorithmTypeSHA3_384,
		cdx.HashAlgoSHA3_512:         hashesentry.HashAlgorithmTypeSHA3_512,
		cdx.HashAlgoBlake2b_256:      hashesentry.HashAlgorithmTypeBLAKE2B_256,
		cdx.HashAlgoBlake2b_384:      hashesentry.HashAlgorithmTypeBLAKE2B_384,
		cdx.HashAlgoBlake2b_512:      hashesentry.HashAlgorithmTypeBLAKE2B_512,
		cdx.HashAlgoBlake3:           hashesentry.HashAlgorithmTypeBLAKE3,
		cdx.HashAlgorithm("invalid"): hashesentry.HashAlgorithmTypeUNKNOWN,
	} {
		res := cdxHashAlg(c).Unserialize(r, nil, nil)
		s.Require().Equal(p, res)
	}
}

func (s *entCDXsuite) TestCDXExtRefTypeToProtobomType() {
	r := bytes.NewReader([]byte(""))

	for cdxRefType, protoType := range map[cdx.ExternalReferenceType]externalreference.Type{
		cdx.ERTypeAttestation:                      externalreference.TypeATTESTATION,
		cdx.ERTypeBOM:                              externalreference.TypeBOM,
		cdx.ERTypeBuildMeta:                        externalreference.TypeBUILD_META,
		cdx.ERTypeBuildSystem:                      externalreference.TypeBUILD_SYSTEM,
		cdx.ERTypeCertificationReport:              externalreference.TypeCERTIFICATION_REPORT,
		cdx.ERTypeChat:                             externalreference.TypeCHAT,
		cdx.ERTypeCodifiedInfrastructure:           externalreference.TypeCODIFIED_INFRASTRUCTURE,
		cdx.ERTypeComponentAnalysisReport:          externalreference.TypeCOMPONENT_ANALYSIS_REPORT,
		cdx.ExternalReferenceType("configuration"): externalreference.TypeCONFIGURATION,
		cdx.ERTypeDistributionIntake:               externalreference.TypeDISTRIBUTION_INTAKE,
		cdx.ERTypeDistribution:                     externalreference.TypeDOWNLOAD,
		cdx.ERTypeDocumentation:                    externalreference.TypeDOCUMENTATION,
		cdx.ERTypeDynamicAnalysisReport:            externalreference.TypeDYNAMIC_ANALYSIS_REPORT,
		cdx.ExternalReferenceType("evidence"):      externalreference.TypeEVIDENCE,
		cdx.ExternalReferenceType("formulation"):   externalreference.TypeFORMULATION,
		cdx.ERTypeIssueTracker:                     externalreference.TypeISSUE_TRACKER,
		cdx.ERTypeLicense:                          externalreference.TypeLICENSE,
		cdx.ExternalReferenceType("log"):           externalreference.TypeLOG,
		cdx.ERTypeMailingList:                      externalreference.TypeMAILING_LIST,
		cdx.ERTypeMaturityReport:                   externalreference.TypeMATURITY_REPORT,
		cdx.ExternalReferenceType("model-card"):    externalreference.TypeMODEL_CARD,
		cdx.ERTypeOther:                            externalreference.TypeOTHER,
		cdx.ExternalReferenceType("poam"):          externalreference.TypePOAM,
		cdx.ERTypeQualityMetrics:                   externalreference.TypeQUALITY_METRICS,
		cdx.ERTypeReleaseNotes:                     externalreference.TypeRELEASE_NOTES,
		cdx.ERTypeRiskAssessment:                   externalreference.TypeRISK_ASSESSMENT,
		cdx.ERTypeRuntimeAnalysisReport:            externalreference.TypeRUNTIME_ANALYSIS_REPORT,
		cdx.ERTypeAdversaryModel:                   externalreference.TypeSECURITY_ADVERSARY_MODEL,
		cdx.ERTypeAdvisories:                       externalreference.TypeSECURITY_ADVISORY,
		cdx.ERTypeSecurityContact:                  externalreference.TypeSECURITY_CONTACT,
		cdx.ERTypePentestReport:                    externalreference.TypeSECURITY_PENTEST_REPORT,
		cdx.ERTypeThreatModel:                      externalreference.TypeSECURITY_THREAT_MODEL,
		cdx.ERTypeSocial:                           externalreference.TypeSOCIAL,
		cdx.ERTypeStaticAnalysisReport:             externalreference.TypeSTATIC_ANALYSIS_REPORT,
		cdx.ERTypeSupport:                          externalreference.TypeSUPPORT,
		cdx.ERTypeVCS:                              externalreference.TypeVCS,
		cdx.ERTypeVulnerabilityAssertion:           externalreference.TypeVULNERABILITY_ASSERTION,
		cdx.ERTypeExploitabilityStatement:          externalreference.TypeVULNERABILITY_EXPLOITABILITY_ASSESSMENT,
		cdx.ERTypeWebsite:                          externalreference.TypeWEBSITE,
		cdx.ExternalReferenceType("invalid"):       externalreference.TypeOTHER,
	} {
		res := cdxExtRefType(cdxRefType).Unserialize(r, nil, nil)
		s.Require().Equal(protoType, res)
	}
}

func TestEntCDXSuite(t *testing.T) {
	suite.Run(t, new(entCDXsuite))
}
