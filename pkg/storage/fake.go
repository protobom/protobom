package storage

import (
	"github.com/bom-squad/protobom/pkg/sbom"
	soptions "github.com/protobom/storage/pkg/options"
)

// Fake is a mock implementation of a storage backend that can be programmed
// to return anything. This fake backend does not store anything, its meant
// only for writing integration tests.
type Fake struct {
	StoreReturns    error
	RetrieveReturns struct {
		Document *sbom.Document
		Error    error
	}
}

func (f *Fake) Store(doc *sbom.Document, opts *soptions.StoreOptions) error {
	return f.StoreReturns
}

func (f *Fake) Retrieve(id string, opts *soptions.RetrieveOptions) (*sbom.Document, error) {
	return f.RetrieveReturns.Document, f.RetrieveReturns.Error
}
