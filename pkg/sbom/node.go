package sbom

import (
	"sort"
	"strings"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
)

// This file contains methods to work with the generated node type
// updates to the node proto should also be reflected in most of these
// functions as they operate on the Node's fields

// Update updates a node's fields with information from the second node
// Any fields in n2 which are not null (empty string, lists longer than 0 or not nill
// pointers will overwrite fields in Node n.
func (n *Node) Update(n2 *Node) {
	if n2.Name != "" {
		n.Name = n2.Name
	}
	if n2.Version != "" {
		n.Version = n2.Version
	}
	if n2.FileName != "" {
		n.FileName = n2.FileName
	}
	if n2.UrlHome != "" {
		n.UrlHome = n2.UrlHome
	}
	if n2.UrlDownload != "" {
		n.UrlDownload = n2.UrlDownload
	}
	if len(n2.Licenses) > 0 {
		n.Licenses = n2.Licenses
	}
	if n2.LicenseConcluded != "" {
		n.LicenseConcluded = n2.LicenseConcluded
	}
	if n2.LicenseComments != "" {
		n.LicenseComments = n2.LicenseComments
	}
	if n2.Copyright != "" {
		n.Copyright = n2.Copyright
	}
	if len(n2.Hashes) > 0 {
		n.Hashes = n2.Hashes
	}
	if n2.SourceInfo != "" {
		n.SourceInfo = n2.SourceInfo
	}
	if n2.PrimaryPurpose != "" {
		n.PrimaryPurpose = n2.PrimaryPurpose
	}
	if n2.Comment != "" {
		n.Comment = n2.Comment
	}
	if n2.Summary != "" {
		n.Summary = n2.Summary
	}
	if n2.Description != "" {
		n.Description = n2.Description
	}
	if len(n2.Attribution) > 0 {
		n.Attribution = n2.Attribution
	}
	if len(n2.Suppliers) > 0 {
		n.Suppliers = n2.Suppliers
	}
	if len(n2.Originators) > 0 {
		n.Originators = n2.Originators
	}
	if n2.ReleaseDate != nil {
		n.ReleaseDate = n2.ReleaseDate
	}
	if n2.BuildDate != nil {
		n.BuildDate = n2.BuildDate
	}
	if n2.ValidUntilDate != nil {
		n.ValidUntilDate = n2.ValidUntilDate
	}
	if len(n2.ExternalReferences) > 0 {
		n.ExternalReferences = n2.ExternalReferences
	}
	if len(n2.Identifiers) > 0 {
		n.Identifiers = n2.Identifiers
	}
	if len(n2.FileTypes) > 0 {
		n.FileTypes = n2.FileTypes
	}
}

// Augment takes updates fields in n with data from n2 which is not already defined
// (not empty string, not 0 length string, not nill pointer).
func (n *Node) Augment(n2 *Node) {
	if n.Name == "" && n2.Name != "" {
		n.Name = n2.Name
	}
	if n.Version == "" && n2.Version != "" {
		n.Version = n2.Version
	}
	if n.FileName == "" && n2.FileName != "" {
		n.FileName = n2.FileName
	}
	if n.UrlHome == "" && n2.UrlHome != "" {
		n.UrlHome = n2.UrlHome
	}
	if n.UrlDownload == "" && n2.UrlDownload != "" {
		n.UrlDownload = n2.UrlDownload
	}
	if len(n.Licenses) == 0 && len(n2.Licenses) > 0 {
		n.Licenses = n2.Licenses
	}
	if n.LicenseConcluded == "" && n2.LicenseConcluded != "" {
		n.LicenseConcluded = n2.LicenseConcluded
	}
	if n.LicenseComments == "" && n2.LicenseComments != "" {
		n.LicenseComments = n2.LicenseComments
	}
	if n.Copyright == "" && n2.Copyright != "" {
		n.Copyright = n2.Copyright
	}
	if len(n.Hashes) == 0 && len(n2.Hashes) > 0 {
		n.Hashes = n2.Hashes
	}
	if n.SourceInfo == "" && n2.SourceInfo != "" {
		n.SourceInfo = n2.SourceInfo
	}
	if n.PrimaryPurpose == "" && n2.PrimaryPurpose != "" {
		n.PrimaryPurpose = n2.PrimaryPurpose
	}
	if n.Comment == "" && n2.Comment != "" {
		n.Comment = n2.Comment
	}
	if n.Summary == "" && n2.Summary != "" {
		n.Summary = n2.Summary
	}
	if n.Description == "" && n2.Description != "" {
		n.Description = n2.Description
	}
	if len(n.Attribution) == 0 && len(n2.Attribution) > 0 {
		n.Attribution = n2.Attribution
	}
	if len(n.Suppliers) == 0 && len(n2.Suppliers) > 0 {
		n.Suppliers = n2.Suppliers
	}
	if len(n.Originators) == 0 && len(n2.Originators) > 0 {
		n.Originators = n2.Originators
	}
	if n.ReleaseDate == nil && n2.ReleaseDate != nil {
		n.ReleaseDate = n2.ReleaseDate
	}
	if n.BuildDate == nil && n2.BuildDate != nil {
		n.BuildDate = n2.BuildDate
	}
	if n.ValidUntilDate == nil && n2.ValidUntilDate != nil {
		n.ValidUntilDate = n2.ValidUntilDate
	}
	if len(n.ExternalReferences) == 0 && len(n2.ExternalReferences) > 0 {
		n.ExternalReferences = n2.ExternalReferences
	}
	if len(n.Identifiers) == 0 && len(n2.Identifiers) > 0 {
		n.Identifiers = n2.Identifiers
	}
	if len(n.FileTypes) == 0 && len(n2.FileTypes) > 0 {
		n.FileTypes = n2.FileTypes
	}
}

// Copy returns a new node that is a copy of the node
func (n *Node) Copy() *Node {
	return &Node{
		Id:                 n.Id,
		Type:               n.Type,
		Name:               n.Name,
		Version:            n.Version,
		FileName:           n.FileName,
		UrlHome:            n.UrlHome,
		UrlDownload:        n.UrlDownload,
		Licenses:           n.Licenses,
		LicenseConcluded:   n.LicenseConcluded,
		LicenseComments:    n.LicenseComments,
		Copyright:          n.Copyright,
		Hashes:             n.Hashes,
		SourceInfo:         n.SourceInfo,
		PrimaryPurpose:     n.PrimaryPurpose,
		Comment:            n.Comment,
		Summary:            n.Summary,
		Description:        n.Description,
		Attribution:        n.Attribution,
		Suppliers:          n.Suppliers,
		Originators:        n.Originators,
		ReleaseDate:        n.ReleaseDate,
		BuildDate:          n.BuildDate,
		ValidUntilDate:     n.ValidUntilDate,
		ExternalReferences: n.ExternalReferences,
		Identifiers:        n.Identifiers,
		FileTypes:          n.FileTypes,
	}
}

// Equal compares Node n to n2 and returns true if they are the same
func (n *Node) Equal(n2 *Node) bool {
	if n2 == nil {
		return false
	}
	return n.flatString() == n2.flatString()
}

// flatString returns a string representation of the node which can be used to
// index the node or compare it against another
func (n *Node) flatString() string {
	pairs := []string{}
	n.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		pairs = append(pairs, string(fd.FullName())+":"+v.String())
		return true
	})

	sort.Strings(pairs)
	return strings.Join(pairs, ":")
}

type PackageURL string

// Purl returns the node purl as a string
func (n *Node) Purl() PackageURL {
	if n.Type == Node_FILE {
		return ""
	}

	for _, e := range n.ExternalReferences {
		if e.Type == "purl" {
			return PackageURL(e.Url)
		}
	}

	return ""
}
