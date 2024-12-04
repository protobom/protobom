package sbom

import (
	"time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type NodeDiff struct {
	NodeId    string
	Added     *Node
	Removed   *Node
	DiffCount int
}

// Diff analyses a node and returns a a new node populated with all fields
// that are different in n2 from n. If no changes are found, Diff returns nil
func (n *Node) Diff(n2 *Node) *NodeDiff {
	nd := NodeDiff{
		NodeId:  n.Id,
		Added:   &Node{},
		Removed: &Node{},
	}

	a, r, c := diff(n.Id, n2.Id)
	nd.Added.Id = a
	nd.Removed.Id = r
	nd.DiffCount += c

	if n.Type != n2.Type {
		nd.Added.Type = n2.Type
		nd.DiffCount++
	}

	a, r, c = diff(n.Name, n2.Name)
	nd.Added.Name = a
	nd.Removed.Name = r
	nd.DiffCount += c

	a, r, c = diff(n.Version, n2.Version)
	nd.Added.Version = a
	nd.Removed.Version = r
	nd.DiffCount += c

	a, r, c = diff(n.FileName, n2.FileName)
	nd.Added.FileName = a
	nd.Removed.FileName = r
	nd.DiffCount += c

	a, r, c = diff(n.UrlHome, n2.UrlHome)
	nd.Added.UrlHome = a
	nd.Removed.UrlHome = r
	nd.DiffCount += c

	a, r, c = diff(n.UrlDownload, n2.UrlDownload)
	nd.Added.UrlDownload = a
	nd.Removed.UrlDownload = r
	nd.DiffCount += c

	a, r, c = diff(n.LicenseConcluded, n2.LicenseConcluded)
	nd.Added.LicenseConcluded = a
	nd.Removed.LicenseConcluded = r
	nd.DiffCount += c

	a, r, c = diff(n.LicenseComments, n2.LicenseComments)
	nd.Added.LicenseComments = a
	nd.Removed.LicenseComments = r
	nd.DiffCount += c

	a, r, c = diff(n.Copyright, n2.Copyright)
	nd.Added.Copyright = a
	nd.Removed.Copyright = r
	nd.DiffCount += c

	a, r, c = diff(n.SourceInfo, n2.SourceInfo)
	nd.Added.SourceInfo = a
	nd.Removed.SourceInfo = r
	nd.DiffCount += c

	ap, rp, cp := diffSlice(n.PrimaryPurpose, n2.PrimaryPurpose)
	nd.Added.PrimaryPurpose = ap
	nd.Removed.PrimaryPurpose = rp
	nd.DiffCount += cp

	a, r, c = diff(n.Comment, n2.Comment)
	nd.Added.Comment = a
	nd.Removed.Comment = r
	nd.DiffCount += c

	a, r, c = diff(n.Summary, n2.Summary)
	nd.Added.Summary = a
	nd.Removed.Summary = r
	nd.DiffCount += c

	a, r, c = diff(n.Description, n2.Description)
	nd.Added.Description = a
	nd.Removed.Description = r
	nd.DiffCount += c

	addedD, removedD, count := diffDates(n.ReleaseDate, n2.ReleaseDate)
	nd.Added.ReleaseDate = addedD
	nd.Removed.ReleaseDate = removedD
	nd.DiffCount += count

	addedD, removedD, count = diffDates(n.BuildDate, n2.BuildDate)
	nd.Added.BuildDate = addedD
	nd.Removed.BuildDate = removedD
	nd.DiffCount += count

	addedD, removedD, count = diffDates(n.ValidUntilDate, n2.ValidUntilDate)
	nd.Added.ValidUntilDate = addedD
	nd.Removed.ValidUntilDate = removedD
	nd.DiffCount += count

	added, removed, count := diffSlice(n.Licenses, n2.Licenses)
	nd.Added.Licenses = added
	nd.Removed.Licenses = removed
	nd.DiffCount += count

	added, removed, count = diffSlice(n.Attribution, n2.Attribution)
	nd.Added.Attribution = added
	nd.Removed.Attribution = removed
	nd.DiffCount += count

	added, removed, count = diffSlice(n.FileTypes, n2.FileTypes)
	nd.Added.FileTypes = added
	nd.Removed.FileTypes = removed
	nd.DiffCount += count

	addedP, removedP, count := diffList(n.Suppliers, n2.Suppliers)
	nd.Added.Suppliers = addedP
	nd.Removed.Suppliers = removedP
	nd.DiffCount += count

	addedP, removedP, count = diffList(n.Originators, n2.Originators)
	nd.Added.Originators = addedP
	nd.Removed.Originators = removedP
	nd.DiffCount += count

	addedER, removedER, count := diffList(n.ExternalReferences, n2.ExternalReferences)
	nd.Added.ExternalReferences = addedER
	nd.Removed.ExternalReferences = removedER
	nd.DiffCount += count

	addedM, removedM, count := diffMap(n.Identifiers, n2.Identifiers)
	nd.Added.Identifiers = addedM
	nd.Removed.Identifiers = removedM
	nd.DiffCount += count

	addedM, removedM, count = diffMap(n.Hashes, n2.Hashes)
	nd.Added.Hashes = addedM
	nd.Removed.Hashes = removedM
	nd.DiffCount += count

	addedPr, removedPr, count := diffList(n.Properties, n2.Properties)
	nd.Added.Properties = addedPr
	nd.Removed.Properties = removedPr
	nd.DiffCount += count

	if nd.DiffCount > 0 {
		return &nd
	}
	return nil
}

type Flattenable interface {
	flatString() string
}

func diffList[T Flattenable](list1, list2 []T) (added, removed []T, count int) {
	added = []T{}
	removed = []T{}

	idx1 := map[string]T{}
	idx2 := map[string]T{}

	for _, el := range list1 {
		flatStr := el.flatString()
		idx1[flatStr] = el
	}
	for _, el := range list2 {
		flatStr := el.flatString()
		idx2[flatStr] = el
	}

	for _, el := range list2 {
		flatStr := el.flatString()
		if _, ok := idx1[flatStr]; !ok {
			added = append(added, el)
		}
	}

	for _, el := range list1 {
		flatStr := el.flatString()
		if _, ok := idx2[flatStr]; !ok {
			removed = append(removed, el)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

func diff[T comparable](v1, v2 T) (added, removed T, count int) {
	// Check if v1 and v2 are equal
	if v1 == v2 {
		var zero T // Initialize a zero value of type T
		return zero, zero, 0
	}

	// Check if v2 is a zero value
	var zero T
	if v2 == zero {
		return zero, v1, 1
	}
	return v2, zero, 1
}

// diffDates takes two dates, compares them and returns d2 in added if there is
// a change, s1 in removed if d2 is nil. count will be 1 if there was a change.
func diffDates(dt1, dt2 *timestamppb.Timestamp) (added, removed *timestamppb.Timestamp, count int) {
	var d1, d2 *time.Time
	if dt1 != nil {
		da1 := dt1.AsTime()
		d1 = &da1
	}
	if dt2 != nil {
		da2 := dt2.AsTime()
		d2 = &da2
	}
	if (d1 != nil && d2 != nil && d1.Unix() != d2.Unix()) || (d1 == nil && d2 != nil) {
		return dt2, nil, 1
	} else if d1 != nil && d2 == nil {
		return nil, dt1, 1
	}
	return nil, nil, 0
}

// diffMap compares two maps and returns what was added and removed
func diffMap[K comparable, V comparable](map1, map2 map[K]V) (added, removed map[K]V, count int) {
	added = make(map[K]V)
	removed = make(map[K]V)

	for k, v2 := range map2 {
		if v1, ok := map1[k]; ok {
			if v1 != v2 {
				added[k] = v2
			}
		} else {
			added[k] = v2
		}
	}

	for k, v1 := range map1 {
		if _, ok := map2[k]; !ok {
			removed[k] = v1
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// diffSlice compares two slices and returns what was added and removed
func diffSlice[T comparable](arr1, arr2 []T) (added, removed []T, count int) {
	added = []T{}
	removed = []T{}

	for _, s := range arr2 {
		if !contains(arr1, s) {
			added = append(added, s)
		}
	}

	for _, s := range arr1 {
		if !contains(arr2, s) {
			removed = append(removed, s)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// contains checks if a slice contains a specific element
func contains[T comparable](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
