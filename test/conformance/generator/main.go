package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// This is a simple utility to generate the golden samples of the conformance
// tests. When run, the raw protobuf equivalents of all format samples will
// be rewritten using the latest models.
//
// This is designed to be run from make conformance but can be run by pointing
// it to the testdata directory:
//
//	go run ./test/conformance/generator/ test/conformance/testdata
//
// This program should only be run when the serialization or unserialization is
// expected to change, such as when proto files are modified.
func main() {
	if len(os.Args) < 2 {
		logrus.Fatal("testdata dir not specified")
	}
	r := reader.New()
	testDataDir := os.Args[1]
	for _, format := range formats.List {
		logrus.Infof("Generating tests for %s-%s (%s)", format.Type(), format.Version(), format.Encoding())
		dataDir := filepath.Join(testDataDir, format.Type(), format.Version(), format.Encoding())
		files, err := os.ReadDir(dataDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logrus.Warnf("No conformance data available for %s", string(format))
				continue
			}
			logrus.Fatalf("error reading dir %s: %s", dataDir, err)
		}

		for _, f := range files {
			if filepath.Ext(f.Name()) == ".proto" {
				continue
			}
			sbomPath := filepath.Join(dataDir, f.Name())
			sbom, err := r.ParseFile(sbomPath)
			if err != nil {
				logrus.Fatalf("reading sbom from %s: %s", f.Name(), err)
			}
			raw, err := proto.Marshal(sbom)
			if err != nil {
				logrus.Fatalf("marshalling sbom to protobuf: %v", err)
			}

			if err := os.WriteFile(sbomPath+".proto", raw, os.FileMode(0o644)); err != nil {
				logrus.Fatalf("wiriting protobuf of %s: %v", f.Name(), err)
			}
			logrus.Infof("Wrote %s sample to %s", format, sbomPath+".proto")
		}
	}
}
