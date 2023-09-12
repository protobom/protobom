package unserializers

import (
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type UnserializerCDX15 struct {
	UnserializerCDX14
}

// ParseStream reads a CycloneDX 1.5 from stream r usinbg the offcial CycloneDX
// libraries and returns a protobom document with its data.
func (u *UnserializerCDX15) ParseStream(_ *options.Options, r io.Reader) (*sbom.Document, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding cyclonedx: %w", err)
	}

	md := &sbom.Metadata{
		Id:      bom.SerialNumber,
		Version: fmt.Sprintf("%d", bom.Version),
		// Name:    ,
		Date:          &timestamppb.Timestamp{},
		Tools:         []*sbom.Tool{},
		Authors:       []*sbom.Person{},
		DocumentTypes: []*sbom.DocumentType{},
	}

	doc := &sbom.Document{
		Metadata: md,
		NodeList: &sbom.NodeList{},
	}

	metadata := bom.Metadata
	if metadata.Lifecycles != nil {
		for _, lc := range *metadata.Lifecycles {
			lc := lc
			name := lc.Name
			desc := lc.Description
			t := u.phaseToSBOMType(&lc.Phase)
			if name == "" {
				name = string(lc.Phase)
			}

			md.DocumentTypes = append(md.DocumentTypes, &sbom.DocumentType{
				Name:        &name,
				Description: &desc,
				Type:        t,
			})
		}
	}
	if bom.Metadata.Component != nil {
		nl, err := u.componentToNodeList(bom.Metadata.Component)
		if err != nil {
			return nil, fmt.Errorf("converting main bom component to node: %w", err)
		}
		if len(nl.RootElements) > 1 {
			logrus.Warnf("root nodelist has %d components, this should not happen", len(nl.RootElements))
		}
		doc.NodeList.Add(nl)
	}

	// Cycle all components and get their graph fragments
	for i := range *bom.Components {
		nl, err := u.componentToNodeList(&(*bom.Components)[i])
		if err != nil {
			return nil, fmt.Errorf("converting component to node: %w", err)
		}

		if len(doc.NodeList.RootElements) == 0 {
			doc.NodeList.Add(nl)
		} else {
			if err := doc.NodeList.RelateNodeListAtID(nl, doc.NodeList.RootElements[0], sbom.Edge_contains); err != nil {
				return nil, fmt.Errorf("relating components to root node: %w", err)
			}
		}
	}

	return doc, nil
}

// phaseToSBOMType converts a CycloneDX lifecycle phase to an SBOM document type
// note that most of the CycloneDX phases are not mapped to SBOM document types and they would be used as OTHER
// this is a temporary solution until we have a better mapping
// see: https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf
func (u *UnserializerCDX15) phaseToSBOMType(ph *cdx.LifecyclePhase) *sbom.DocumentType_SBOMType {
	phase := *ph
	switch phase {
	case cdx.LifecyclePhaseBuild:
		return sbom.DocumentType_BUILD.Enum()
	case cdx.LifecyclePhaseDecommission:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhaseDesign:
		return sbom.DocumentType_DESIGN.Enum()
	case cdx.LifecyclePhaseDiscovery:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhaseOperations:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhasePostBuild:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhasePreBuild:
		return sbom.DocumentType_OTHER.Enum()
	default:
		return nil
	}
}
