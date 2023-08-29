package reader

import (
	"fmt"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/unserializer"
	spdxjson "github.com/spdx/tools-golang/json"
)

type Reader struct {
	cdx      unserializer.CDXUnserializer
	spdx23   unserializer.SPDX23Unserializer
	encoding string
	sniffer  formats.Sniffer
}

func New(opts ...ReaderOption) *Reader {
	r := &Reader{
		cdx:      &unserializer.UnserializerCDX{},
		spdx23:   &unserializer.UnserializerSPDX23{},
		encoding: formats.JSON,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func (r *Reader) parseCDX(re io.Reader) (*sbom.Document, error) {
	bom := new(cdx.BOM)

	var format cdx.BOMFileFormat
	if r.encoding == formats.XML {
		format = cdx.BOMFileFormatXML
	} else if r.encoding == formats.JSON {
		format = cdx.BOMFileFormatJSON
	} else {
		return nil, fmt.Errorf("unknown encoding: %s", r.encoding)
	}

	decoder := cdx.NewBOMDecoder(re, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding cyclonedx: %w", err)
	}

	doc := sbom.NewDocument()

	// Metadata
	md, nl, err := r.cdx.Metadata(bom)
	if err != nil {
		return nil, fmt.Errorf("converting metadata: %w", err)
	}

	doc.Metadata = md
	doc.NodeList = nl

	// Cycle all components and get their graph fragments
	for i := range *bom.Components {
		components := (*bom.Components)[i]
		nl, err := r.cdx.NodeList(&components)
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

func (r *Reader) parseSPDX(format formats.Format, re io.Reader) (*sbom.Document, error) {
	var document *sbom.Document
	if format.Version() == "2.3" {
		doc, err := r.parseSPDX23(re)
		if err != nil {
			return nil, fmt.Errorf("parsing SPDX 2.3: %w", err)
		}

		document = doc
	}

	if document == nil {
		return nil, fmt.Errorf("unknown SPDX version: %s", format.Version())
	}

	return document, nil
}

func (r *Reader) parseSPDX23(re io.Reader) (*sbom.Document, error) {
	bom, err := spdxjson.Read(re)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX json: %w", err)
	}

	doc := sbom.NewDocument()

	// Metadata
	md, nl, err := r.spdx23.Metadata(bom)
	if err != nil {
		return nil, fmt.Errorf("converting metadata: %w", err)
	}

	doc.Metadata = md
	doc.NodeList = nl

	// NodeList, relationships and root elements
	nodelist, err := r.spdx23.NodeList(bom)
	if err != nil {
		return nil, fmt.Errorf("converting nodelist: %w", err)
	}

	doc.NodeList.Add(nodelist)
	return doc, nil
}

// ParseFile reads a file and returns an sbom.Document
func (r *Reader) ParseFile(path string) (*sbom.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer f.Close()

	return r.ParseStream(f)
}

// ParseStream returns a document from a io reader
func (r *Reader) ParseStream(f io.ReadSeeker) (*sbom.Document, error) {
	format, err := r.DetectFormat(f)
	if err != nil {
		return nil, fmt.Errorf("detecting SBOM format: %w", err)
	}

	var doc *sbom.Document
	t := format.Type()
	if t == formats.SPDXFORMAT {
		doc, err = r.parseSPDX(format, f)
		if err != nil {
			return nil, fmt.Errorf("parsing SPDX: %w", err)
		}
	}

	if t == formats.CDXFORMAT {
		doc, err = r.parseCDX(f)
		if err != nil {
			return nil, fmt.Errorf("parsing CycloneDX: %w", err)
		}
	}

	return doc, err
}

func (r *Reader) DetectFormat(rs io.ReadSeeker) (formats.Format, error) {
	format, err := r.sniffer.SniffReader(rs)
	if err != nil {
		return "", fmt.Errorf("detecting format: %w", err)
	}
	return format, nil
}
