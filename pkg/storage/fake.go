package storage

import (
	"github.com/protobom/protobom/pkg/sbom"
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

func (f *Fake) Store(doc *sbom.Document, opts *StoreOptions) error {
	return f.StoreReturns
}

func (f *Fake) Retrieve(id string, opts *RetrieveOptions) (*sbom.Document, error) {
	return f.RetrieveReturns.Document, f.RetrieveReturns.Error
}
