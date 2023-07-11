package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bom-squad/protobom/cmd/cli"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var filename = filepath.Join(os.TempDir(), "sbom.proto") //nolint:unused

// NOTICE:
// This program is a demo to test the protobom functions while
// we have a proper CLI and tests. It can be run directly.
// It expects an SBOM as its first argument and it will perform
// some tricks based on the following lines. See comments below

func main() {
	cli.Execute()
}

//nolint:unused
func writeProto(bom *sbom.Document) {
	out, err := proto.Marshal(bom)
	if err != nil {
		logrus.Fatalf("marshalling sbom to protobuf: %v", err)
	}

	if err := os.WriteFile(filename, out, os.FileMode(0o644)); err != nil {
		logrus.Fatalf("writing data to disk: %v", err)
	}
}

//nolint:unused
func readProto() *sbom.Document {
	data, err := os.ReadFile(filename)
	if err != nil {
		logrus.Fatal(fmt.Errorf("reading proto data: %v", err))
	}
	bom := &sbom.Document{}
	if err := proto.Unmarshal(data, bom); err != nil {
		logrus.Fatal(fmt.Errorf("unmarshaling protobuf: %v", err))
	}
	return bom
}
