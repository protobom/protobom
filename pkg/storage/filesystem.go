package storage

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/release-utils/util"
)

var _ StoreRetriever = (*FileSystem)(nil)

type FileSystemOptions struct {
	// Path is the path top the directory where the storage
	// backend will store the document data.
	Path string
}

// FileSystem is the default persistence drive of protobom. It is a simple
// implementation that writes protobom data to a directory. It is keyed by
// filename.
type FileSystem struct {
	Options FileSystemOptions
}

func NewFileSystem() *FileSystem {
	return &FileSystem{
		Options: FileSystemOptions{},
	}
}

func generateDocFileName(documentId string) (string, error) {
	if documentId == "" {
		return "", fmt.Errorf("unable to generate filename, document ID not set")
	}
	return fmt.Sprintf("%x.protobom", sha256.Sum256([]byte(documentId))), nil
}

// Store implements the backend driver Store method. It stores a marshalled protobom
// in binary form to a data directory.
func (fs *FileSystem) Store(bom *sbom.Document, opts *StoreOptions) error {
	// Support nil options
	if opts == nil {
		opts = &StoreOptions{}
	}

	i, err := os.Stat(fs.Options.Path)
	switch {
	// Check if the data directory exists
	case err != nil && errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(fs.Options.Path, os.FileMode(0o644)); err != nil {
			return fmt.Errorf("error creating filesystem backend storage directory")
		}
	case err != nil:
		// Any other errors are a true error
		return fmt.Errorf("checking filesystem backend path directory: %w", err)
	case !i.IsDir():
		return fmt.Errorf("the specified filsystem backend patch is not a directory")
	}

	if bom.Metadata == nil || bom.Metadata.Id == "" {
		return fmt.Errorf("unable to persist document: no document id set")
	}

	// Marshal the proto to binary form
	out, err := proto.Marshal(bom)
	if err != nil {
		return fmt.Errorf("marshalling protobom to binary form: %w", err)
	}

	filename, err := generateDocFileName(bom.Metadata.Id)
	if err != nil {
		return err
	}

	if opts.NoClobber && util.Exists(filepath.Join(fs.Options.Path, filename)) {
		return fmt.Errorf("there is already an entry for the specified document (and NoClobber = true)")
	}

	if err := os.WriteFile(filepath.Join(fs.Options.Path, filename), out, os.FileMode(0o644)); err != nil {
		return fmt.Errorf("writing data to disk: %w", err)
	}

	return nil
}

// Retrieve implements the storage backend Retrieve interface. It looks for a
// protobom document in a directory
func (fs *FileSystem) Retrieve(id string, _ *RetrieveOptions) (*sbom.Document, error) {
	if fs.Options.Path == "" {
		return nil, fmt.Errorf("unable to retrieve SBOM data: filesystem backend data dir not set")
	}
	if id == "" {
		return nil, fmt.Errorf("unable to retrieve SBOM data: no identifier defined")
	}

	filename, err := generateDocFileName(id)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(fs.Options.Path, filename))
	if err != nil {
		logrus.Fatal(fmt.Errorf("reading protobom data from disk: %v", err))
	}
	bom := &sbom.Document{}
	if err := proto.Unmarshal(data, bom); err != nil {
		logrus.Fatal(fmt.Errorf("unmarshaling protobom data: %v", err))
	}

	return bom, nil
}
