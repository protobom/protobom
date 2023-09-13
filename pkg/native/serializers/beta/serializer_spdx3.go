package beta

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
)

var _ native.Serializer = &SPDX3{}

type SPDX3Options struct {
	Indent int
}

func init() {
	writer.RegisterSerializer(formats.Format("text/spdx+json;version=3.0"), &SPDX3{})
}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

//nolint:unused // Document will be used when supporting JSON-LD framed mode
type document struct {
	Context string        `json:"@context"`
	Graph   []interface{} `json:"@graph"`
}

//nolint:unused // SPDX Document will be used when supporting JSON-LD framed mode
type spdxDocument struct {
	Type         string   `json:"type"` // SpdxDocument
	CreationInfo string   `json:"creationInfo,omitempty"`
	Name         string   `json:"name"`
	Elements     []string `json:"element"`
	RootElements []string `json:"rootElement"`
}

type sbomType struct {
	Type         string        `json:"type"` // Sbom
	CreationInfo *creationInfo `json:"creationInfo,omitempty"`
	SbomType     string        `json:"sbomType,omitempty"`
	Elements     []interface{} `json:"element"` // o strings?
	RootElements []string      `json:"rootElement"`
}

type creationInfo struct {
	ID          string     `json:"@id,omitempty"`
	Type        string     `json:"type"` // SpdxDocument
	SpecVersion string     `json:"specVersion"`
	Created     *time.Time `json:"created"`
	CreatedBy   []string   `json:"createdBy,omitempty"`
	Profiles    []string   `json:"profile,omitempty"`
	DataLicense string     `json:"dataLicense"`
}

type file struct {
	Type              string        `json:"type"` // File
	SpdxId            string        `json:"SpdxId,omitempty"`
	Name              string        `json:"name"`
	ContentType       string        `json:"contentType,omitempty"` // "image/png"
	Purpose           []string      `json:"purpose,omitempty"`
	ContentIdentifier string        `json:"contentIdentifier,omitempty"`
	CreationInfo      *creationInfo `json:"creationInfo,omitempty"`
}
type relationship struct {
	Type             string        `json:"type"` // Relationship
	SpdxId           string        `json:"SpdxId,omitempty"`
	From             string        `json:"from"`
	To               []string      `json:"to"`
	RelationshipType string        `json:"relationshipType"`
	CreationInfo     *creationInfo `json:"creationInfo,omitempty"`
}

type pkg struct {
	ID                 string              `json:"@id,omitempty"`
	Type               string              `json:"type"` // Package
	SpdxId             string              `json:"SpdxId,omitempty"`
	CreationInfo       *creationInfo       `json:"creationInfo,omitempty"`
	Name               string              `json:"name"`
	Summary            string              `json:"summary,omitempty"`
	Description        string              `json:"description,omitempty"`
	Comment            string              `json:"comment,omitempty"`
	Version            string              `json:"packageVersion,omitempty"`
	DownloadLocation   string              `json:"downloadLocation,omitempty"`
	PackageUrl         string              `json:"packageUrl,omitempty"`
	HomePage           string              `json:"homepage,omitempty"`
	Purpose            []string            `json:"purpose,omitempty"`
	ContentIdentifier  string              `json:"contentIdentifier,omitempty"`
	OriginatedBy       []string            `json:"originatedBy,omitempty"`
	SuppliedBy         []string            `json:"suppliedBy,omitempty"`
	VerifiedUsing      []hashList          `json:"verifiedUsing,omitempty"`
	ExternalReferences []externalReference `json:"externalReference,omitempty"`
}

type externalReference struct {
	Type                  string // ExternalReference
	ExternalReferenceType string `json:"externalReferenceType"`
	Locator               []string
}

type hashList struct {
	Type      string // "Hash",
	Algorithm string
	HashValue string `json:"hashValue"`
}

type SPDX3 struct{}

func (spdx3 *SPDX3) Serialize(bom *sbom.Document, _ interface{}) (interface{}, error) {
	now := time.Now()
	spdxSBOM := sbomType{
		Type: "Sbom",
		CreationInfo: &creationInfo{
			Type:        "CreationInfo",
			SpecVersion: "3.0.0",
			Created:     &now,
			CreatedBy:   []string{},
			Profiles:    []string{},
			DataLicense: "https://spdx.org/licenses/CC0-1.0",
		},
		SbomType:     "",
		Elements:     []interface{}{},
		RootElements: []string{},
	}

	// Transfer the ids of the root nodes verbatim
	spdxSBOM.RootElements = bom.NodeList.RootElements

	// Cycle nodes and add them to the elements array
	for _, n := range bom.NodeList.Nodes {
		switch n.Type {
		case sbom.Node_PACKAGE:
			p, err := spdx3.nodeToPackage(n)
			if err != nil {
				return nil, fmt.Errorf("creating package from node: %w", err)
			}
			spdxSBOM.Elements = append(spdxSBOM.Elements, p)
		case sbom.Node_FILE:
			f, err := spdx3.nodeToFile(n)
			if err != nil {
				return nil, fmt.Errorf("converting node to SPDX3 file: %w", err)
			}
			spdxSBOM.Elements = append(spdxSBOM.Elements, f)
		}
	}

	for _, e := range bom.NodeList.Edges {
		r, err := spdx3.edgeToRelationship(e)
		if err != nil {
			return nil, fmt.Errorf("converting edge to SPDX3 relationship: %w", err)
		}
		spdxSBOM.Elements = append(spdxSBOM.Elements, r)
	}

	return spdxSBOM, nil
}

// edgeToRelationship converts a protobom edge to an SPDX3 relationship
func (spdx3 *SPDX3) edgeToRelationship(e *sbom.Edge) (relationship, error) {
	if e.Type.String() == "" {
		return relationship{}, errors.New("unable to serialize relationship without type")
	}
	r := relationship{
		Type:             "Relationship",
		From:             e.From,
		To:               e.To,
		RelationshipType: e.Type.String(),
	}
	return r, nil
}

func (spdx3 *SPDX3) nodeToPackage(n *sbom.Node) (pkg, error) {
	if n.Type != sbom.Node_PACKAGE {
		return pkg{}, fmt.Errorf("attempt to serialize SPDX package from non pkg node")
	}
	p := pkg{
		ID:                 "",
		Type:               "Package",
		SpdxId:             n.Id,
		Name:               n.Name,
		Summary:            n.Summary,
		Description:        n.Description,
		Comment:            n.Comment,
		Version:            n.Version,
		DownloadLocation:   n.UrlDownload,
		PackageUrl:         string(n.Purl()),
		HomePage:           n.UrlHome,
		Purpose:            []string{},
		ContentIdentifier:  "",
		OriginatedBy:       []string{},
		SuppliedBy:         []string{},
		VerifiedUsing:      []hashList{},
		ExternalReferences: []externalReference{},
	}

	for algo, h := range n.Hashes {
		ha := sbom.HashAlgorithm(algo)
		if ha.ToSPDX3() == "" {
			// TODO(degradation): Algoruithm not supperted in SPDX3
			continue
		}
		p.VerifiedUsing = append(p.VerifiedUsing, hashList{
			Type:      "Hash",
			Algorithm: ha.ToSPDX3(),
			HashValue: h,
		})
	}

	for _, ei := range n.ExternalReferences {
		p.ExternalReferences = append(p.ExternalReferences, externalReference{
			Type:                  "ExternalReference",
			ExternalReferenceType: ei.Type,
			Locator:               []string{ei.Url},
		})
	}

	return p, nil
}

func (spdx3 *SPDX3) nodeToFile(n *sbom.Node) (file, error) {
	if n.Type != sbom.Node_FILE {
		return file{}, errors.New("attempt to build a file from a package node")
	}
	f := file{
		Type:              "File",
		SpdxId:            n.Id,
		Name:              n.Name,
		ContentType:       "",
		Purpose:           []string{},
		ContentIdentifier: "",
	}
	return f, nil
}

func (spdx3 *SPDX3) Render(rawDoc interface{}, w io.Writer, o interface{}) error {
	doc, ok := rawDoc.(sbomType)
	if !ok {
		return errors.New("unable to cast SBOM as an SPDX 3.0 SBOM")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", strings.Repeat(" ", o.(SPDX3Options).Indent))
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SBOM: %w", err)
	}
	return nil
}
