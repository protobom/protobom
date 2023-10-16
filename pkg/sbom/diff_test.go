package sbom

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDiffString(t *testing.T) {
	for _, tc := range []struct {
		name            string
		sut1            string
		sut2            string
		expectedAdded   string
		expectedRemoved string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            "a",
			sut2:            "a",
			expectedAdded:   "",
			expectedRemoved: "",
			expectedCount:   0,
		},
		{
			name:            "change",
			sut1:            "",
			sut2:            "a",
			expectedAdded:   "a",
			expectedRemoved: "",
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            "a",
			sut2:            "",
			expectedAdded:   "",
			expectedRemoved: "a",
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffString(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffStrSlice(t *testing.T) {
	for _, tc := range []struct {
		name            string
		sut1            []string
		sut2            []string
		expectedAdded   []string
		expectedRemoved []string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []string{"a", "b"},
			sut2:            []string{"a", "b"},
			expectedAdded:   []string{},
			expectedRemoved: []string{},
			expectedCount:   0,
		},
		{
			name:            "add to blank",
			sut1:            []string{},
			sut2:            []string{"a"},
			expectedAdded:   []string{"a"},
			expectedRemoved: []string{},
			expectedCount:   1,
		},
		{
			name:            "add to existing",
			sut1:            []string{"a"},
			sut2:            []string{"a", "b"},
			expectedAdded:   []string{"b"},
			expectedRemoved: []string{},
			expectedCount:   1,
		},
		{
			name:            "remove all",
			sut1:            []string{"a", "b"},
			sut2:            []string{},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a", "b"},
			expectedCount:   1,
		},
		{
			name:            "remove one",
			sut1:            []string{"a", "b"},
			sut2:            []string{"b"},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a"},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffStrSlice(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffDates(t *testing.T) {
	t1 := timestamppb.New(time.Date(2023, 11, 15, 13, 30, 0, 0, time.UTC))
	t2 := timestamppb.New(time.Date(2000, 1, 1, 13, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		name            string
		sut1            *timestamppb.Timestamp
		sut2            *timestamppb.Timestamp
		expectedAdded   *timestamppb.Timestamp
		expectedRemoved *timestamppb.Timestamp
		expectedCount   int
	}{
		{
			name:            "nochange",
			sut1:            t1,
			sut2:            t1,
			expectedAdded:   nil,
			expectedRemoved: nil,
			expectedCount:   0,
		},
		{
			name:            "nochange blank",
			sut1:            nil,
			sut2:            nil,
			expectedAdded:   nil,
			expectedRemoved: nil,
			expectedCount:   0,
		},
		{
			name:            "change",
			sut1:            t1,
			sut2:            t2,
			expectedAdded:   t2,
			expectedRemoved: nil,
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            t2,
			sut2:            nil,
			expectedAdded:   nil,
			expectedRemoved: t2,
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffDates(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffPersonList(t *testing.T) {
	p1 := &Person{
		Name:  "Corelia Enterprises",
		IsOrg: true,
	}
	p2 := &Person{
		Name:  "Turbowind Enterprises",
		IsOrg: true,
	}
	p3 := &Person{
		Name: "Inky",
	}
	for _, tc := range []struct {
		name            string
		sut1            []*Person
		sut2            []*Person
		expectedAdded   []*Person
		expectedRemoved []*Person
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1, p2},
			expectedAdded:   []*Person{},
			expectedRemoved: []*Person{},
			expectedCount:   0,
		},
		{
			name:            "add",
			sut1:            []*Person{p1},
			sut2:            []*Person{p1, p2},
			expectedAdded:   []*Person{p2},
			expectedRemoved: []*Person{},
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1},
			expectedAdded:   []*Person{},
			expectedRemoved: []*Person{p2},
			expectedCount:   1,
		},
		{
			name:            "add and remove",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1, p3},
			expectedAdded:   []*Person{p3},
			expectedRemoved: []*Person{p2},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffPersonList(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffExtRefList(t *testing.T) {
	er1 := &ExternalReference{
		Url:  "https://example.com/",
		Type: "URL",
	}
	er2 := &ExternalReference{
		Url:  "https://example.net/",
		Type: "URL",
	}
	er3 := &ExternalReference{
		Url:  "https://example.org/",
		Type: "URL",
	}
	for _, tc := range []struct {
		name            string
		sut1            []*ExternalReference
		sut2            []*ExternalReference
		expectedAdded   []*ExternalReference
		expectedRemoved []*ExternalReference
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1, er2},
			expectedAdded:   []*ExternalReference{},
			expectedRemoved: []*ExternalReference{},
			expectedCount:   0,
		},
		{
			name:            "add",
			sut1:            []*ExternalReference{er1},
			sut2:            []*ExternalReference{er1, er2},
			expectedAdded:   []*ExternalReference{er2},
			expectedRemoved: []*ExternalReference{},
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1},
			expectedAdded:   []*ExternalReference{},
			expectedRemoved: []*ExternalReference{er2},
			expectedCount:   1,
		},
		{
			name:            "add and remove",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1, er3},
			expectedAdded:   []*ExternalReference{er3},
			expectedRemoved: []*ExternalReference{er2},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffExtRefList(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffIntStrMap(t *testing.T) {
	m1 := map[int32]string{
		int32(HashAlgorithm_SHA1):   "68e6e3665b3010f0979089079d7f554c940e3aa8",
		int32(HashAlgorithm_SHA256): "d02b22ab7fc76fe2a17e768b180bf5048889dbcae3a6d7e4a889a916848e5d11",
	}
	m2 := map[int32]string{
		int32(HashAlgorithm_SHA1):   "68e6e3665b3010f0979089079d7f554c940e3aa8",
		int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
	}

	for _, tc := range []struct {
		name            string
		sut1            map[int32]string
		sut2            map[int32]string
		expectedAdded   map[int32]string
		expectedRemoved map[int32]string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            m1,
			sut2:            m1,
			expectedAdded:   map[int32]string{},
			expectedRemoved: map[int32]string{},
			expectedCount:   0,
		},
		{
			name: "change",
			sut1: m1,
			sut2: m2,
			expectedAdded: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedRemoved: map[int32]string{},
			expectedCount:   1,
		},
		{
			name: "remove",
			sut1: m1,
			sut2: map[int32]string{
				int32(HashAlgorithm_SHA256): "d02b22ab7fc76fe2a17e768b180bf5048889dbcae3a6d7e4a889a916848e5d11",
			},
			expectedAdded: map[int32]string{},
			expectedRemoved: map[int32]string{
				int32(HashAlgorithm_SHA1): "68e6e3665b3010f0979089079d7f554c940e3aa8",
			},
			expectedCount: 1,
		},
		{
			name: "add and remove",
			sut1: m1,
			sut2: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedAdded: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedRemoved: map[int32]string{
				int32(HashAlgorithm_SHA1): "68e6e3665b3010f0979089079d7f554c940e3aa8",
			},
			expectedCount: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffIntStrMap(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}
