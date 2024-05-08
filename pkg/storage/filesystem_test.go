package storage

import (
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestFileSystem(t *testing.T) {
	t.Parallel()
	fs := NewFileSystem()
	fs.Options.Path = t.TempDir()

	for _, tc := range []struct {
		name      string
		testDoc   *sbom.Document
		shouldErr bool
	}{
		{
			name: "normal i/o",
			testDoc: &sbom.Document{
				Metadata: &sbom.Metadata{Id: "test-document"},
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Write the test document
			err := fs.Store(tc.testDoc, nil)
			if tc.shouldErr {
				require.Error(t, err)
				return
			}

			filename, err := generateDocFileName(tc.testDoc.Metadata.Id)
			require.NoError(t, err)
			require.FileExists(t, filepath.Join(fs.Options.Path, filename))

			doc, err := fs.Retrieve(tc.testDoc.Metadata.Id, nil)
			require.NoError(t, err)
			require.NotNil(t, doc)

			require.Equal(t, tc.testDoc.Metadata.Id, doc.Metadata.Id)
		})
	}
}
