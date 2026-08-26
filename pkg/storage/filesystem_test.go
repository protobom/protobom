package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/sbom"
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

// Storing into a directory that does not exist yet must create it usable:
// a directory without its execute bits cannot be written into afterwards.
func TestFileSystemCreatesDataDir(t *testing.T) {
	t.Parallel()
	fs := NewFileSystem()
	fs.Options.Path = filepath.Join(t.TempDir(), "new", "data")

	doc := &sbom.Document{Metadata: &sbom.Metadata{Id: "created-dir"}}
	require.NoError(t, fs.Store(doc, nil))

	info, err := os.Stat(fs.Options.Path)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.NotZero(t, info.Mode().Perm()&0o100, "data dir must be traversable by its owner")

	got, err := fs.Retrieve("created-dir", nil)
	require.NoError(t, err)
	require.Equal(t, "created-dir", got.Metadata.Id)
}

func TestFileSystemStoreErrors(t *testing.T) {
	t.Parallel()

	t.Run("no data dir configured", func(t *testing.T) {
		t.Parallel()
		err := NewFileSystem().Store(&sbom.Document{Metadata: &sbom.Metadata{Id: "x"}}, nil)
		require.Error(t, err)
	})

	t.Run("nil document", func(t *testing.T) {
		t.Parallel()
		fs := NewFileSystem()
		fs.Options.Path = t.TempDir()
		require.Error(t, fs.Store(nil, nil))
	})

	t.Run("path is a file", func(t *testing.T) {
		t.Parallel()
		fs := NewFileSystem()
		fs.Options.Path = filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(fs.Options.Path, []byte("x"), 0o600))
		require.Error(t, fs.Store(&sbom.Document{Metadata: &sbom.Metadata{Id: "x"}}, nil))
	})

	t.Run("no clobber", func(t *testing.T) {
		t.Parallel()
		fs := NewFileSystem()
		fs.Options.Path = t.TempDir()
		doc := &sbom.Document{Metadata: &sbom.Metadata{Id: "x"}}
		require.NoError(t, fs.Store(doc, nil))
		require.Error(t, fs.Store(doc, &StoreOptions{NoClobber: true}))
		require.NoError(t, fs.Store(doc, &StoreOptions{NoClobber: false}))
	})
}

// Retrieve must report problems as errors: a library must never exit the
// process on a missing or corrupt document.
func TestFileSystemRetrieveErrors(t *testing.T) {
	t.Parallel()
	fs := NewFileSystem()
	fs.Options.Path = t.TempDir()

	t.Run("missing document", func(t *testing.T) {
		t.Parallel()
		doc, err := fs.Retrieve("never-stored", nil)
		require.ErrorIs(t, err, os.ErrNotExist)
		require.Nil(t, doc)
	})

	t.Run("corrupt document", func(t *testing.T) {
		t.Parallel()
		filename, err := generateDocFileName("corrupt")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(fs.Options.Path, filename), []byte{0xff, 0xff, 0xff}, 0o600))
		doc, err := fs.Retrieve("corrupt", nil)
		require.Error(t, err)
		require.Nil(t, doc)
	})

	t.Run("empty id", func(t *testing.T) {
		t.Parallel()
		_, err := fs.Retrieve("", nil)
		require.Error(t, err)
	})
}
