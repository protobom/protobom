// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

package storage

type StoreOptions struct {
	// BackendOptions is a field to pipe system-specific options to the
	// modules implementing the storage backend interface
	BackendOptions any

	// NoClobber ensures documents with the same ID are never overwritten
	NoClobber bool
}

type RetrieveOptions struct {
	// BackendOptions is a field to pipe system-specific options to the
	// modules implementing the storage backend interface
	BackendOptions any
}
