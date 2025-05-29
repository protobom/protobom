package sbom

import (
	"regexp"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestNewNodeIdentifier(t *testing.T) {
	validIDCharsRe := regexp.MustCompile(`^[a-zA-Z0-9-.]+$`)

	for m, tc := range map[string]struct {
		parts  []string
		expect string
	}{
		"no parts":                 {[]string{}, ""},
		"plain node":               {[]string{"node"}, ""},
		"plain node and auto":      {[]string{"node", "auto"}, ""},
		"node and identifier":      {[]string{"node", "hello"}, "protobom-node--hello"},
		"node and auto and string": {[]string{"node", "auto", "my package"}, "protobom-node-auto--my-package"},
		"auto node and string":     {[]string{"auto", "node", "my package"}, "protobom-auto-node--my-package"},
		"one part":                 {[]string{"Hello"}, "protobom--Hello"},
		"invalid chars":            {[]string{"I have invalid char$ and sp@ces"}, ""},
	} {
		id := NewNodeIdentifier(tc.parts...)
		logrus.Info(id)
		require.True(t, validIDCharsRe.MatchString(id), "%s: %s", m, id)
		if tc.expect != "" {
			require.Equal(t, id, tc.expect)
		}
	}
}
