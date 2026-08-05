package serializers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Serializer = &SPDX22{}

// SPDX22 serializes protobom documents to SPDX 2.2 in JSON encoding.
// The document is built with the SPDX 2.3 serializer and downgraded
// through the tools-golang conversion chain, degrading the data that
// SPDX 2.2 cannot express (see downgradeDocument).
type SPDX22 struct {
	SPDX23
}

func NewSPDX22() *SPDX22 {
	return &SPDX22{}
}

// Serialize converts a protobom document to an SPDX 2.2 document. It
// accepts the same raw options as the SPDX 2.3 serializer.
func (s *SPDX22) Serialize(bom *sbom.Document, opts *native.SerializeOptions, rawopts any) (any, error) {
	doc, err := s.SPDX23.Serialize(bom, opts, rawopts)
	if err != nil {
		return nil, err
	}
	doc23, ok := doc.(*spdx.Document)
	if !ok {
		return nil, errors.New("unable to cast serialized document as SPDX 2.3")
	}
	doc22 := v2_2.Document{}
	if err := convert.Document(doc23, &doc22); err != nil {
		return nil, fmt.Errorf("downgrading document to SPDX 2.2: %w", err)
	}
	downgradeDocument(&doc22)
	return &doc22, nil
}

// Render writes a serialized SPDX 2.2 document to the stream in JSON
// encoding.
func (s *SPDX22) Render(doc any, wr io.Writer, o *native.RenderOptions, _ any) error {
	doc22, ok := doc.(*v2_2.Document)
	if !ok {
		return errors.New("unable to cast doc as SPDX 2.2 document")
	}
	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", strings.Repeat(" ", o.Indent))
	if err := encoder.Encode(doc22); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}
	return nil
}

// spdx22ChecksumAlgorithms lists the checksum algorithms SPDX 2.2
// defines. The algorithms 2.3 added (SHA3-*, BLAKE*, ADLER32) are
// dropped when downgrading.
var spdx22ChecksumAlgorithms = map[common.ChecksumAlgorithm]bool{
	common.SHA224: true,
	common.SHA1:   true,
	common.SHA256: true,
	common.SHA384: true,
	common.SHA512: true,
	common.MD2:    true,
	common.MD4:    true,
	common.MD5:    true,
	common.MD6:    true,
}

// downgradeDocument degrades the data of a converted document that
// SPDX 2.2 cannot express: checksum algorithms introduced in 2.3 are
// dropped, and the licensing and copyright fields that 2.3 made
// optional are backfilled with NOASSERTION as 2.2 requires them.
// Fields 2.2 does not have (such as the primary package purpose) are
// already dropped by the struct conversion.
func downgradeDocument(doc *v2_2.Document) {
	for _, p := range doc.Packages {
		p.PackageChecksums = filterChecksums22(p.PackageChecksums)
		if p.PackageDownloadLocation == "" {
			p.PackageDownloadLocation = protospdx.NOASSERTION
		}
		if p.PackageLicenseConcluded == "" {
			p.PackageLicenseConcluded = protospdx.NOASSERTION
		}
		if p.PackageLicenseDeclared == "" {
			p.PackageLicenseDeclared = protospdx.NOASSERTION
		}
		if p.PackageCopyrightText == "" {
			p.PackageCopyrightText = protospdx.NOASSERTION
		}
	}
	for _, f := range doc.Files {
		f.Checksums = filterChecksums22(f.Checksums)
		if f.LicenseConcluded == "" {
			f.LicenseConcluded = protospdx.NOASSERTION
		}
		if len(f.LicenseInfoInFiles) == 0 {
			f.LicenseInfoInFiles = []string{protospdx.NOASSERTION}
		}
		if f.FileCopyrightText == "" {
			f.FileCopyrightText = protospdx.NOASSERTION
		}
	}
}

func filterChecksums22(in []common.Checksum) []common.Checksum {
	out := make([]common.Checksum, 0, len(in))
	for _, c := range in {
		if spdx22ChecksumAlgorithms[c.Algorithm] {
			out = append(out, c)
		}
	}
	return out
}
