package formats

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

var sniffFormats = []sniffFormat{
	cdxSniff{},
	spdxSniff{},
}

type sniffFormat interface {
	sniff(data []byte) formatDetails
}

type Sniffer struct{}

// SniffFile takes a path an return the format
func (fs *Sniffer) SniffFile(path string) (Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening path: %w", err)
	}
	return fs.SniffReader(f)
}

// SniffReader reads a stream and return the SBOM format
func (fs *Sniffer) SniffReader(f io.ReadSeeker) (Format, error) {
	defer f.Seek(0, 0)
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)

	var format formatDetails

	for fileScanner.Scan() {
		sniffFormat := fs.sniff(fileScanner.Bytes())

		if sniffFormat.Type != "" {
			format.Type = sniffFormat.Type
		}
		if sniffFormat.Version != "" {
			format.Version = sniffFormat.Version
		}
		if sniffFormat.Encoding != "" {
			format.Encoding = sniffFormat.Encoding
		}

		if format.Version != "" && format.Type != "" && format.Encoding != "" {
			break
		}
	}

	fmt.Fprintf(
		os.Stderr, "format: %s version: %s encoding: %s\n",
		format.Type, format.Version, format.Encoding,
	)

	for _, f := range List {
		if string(f) == fmt.Sprintf("%s+%s;version=%s", format.Type, format.Encoding, format.Version) {
			return f, nil
		}
	}

	// TODO(puerco): Implement a light parser in case the string hacks don't work
	return "", fmt.Errorf("unknown SBOM format")
}

func (fs *Sniffer) sniff(data []byte) formatDetails {
	for _, sig := range sniffFormats {
		format := sig.sniff(data)
		if format.Type != "" ||
			format.Version != "" ||
			format.Encoding != "" {
			return format
		}
	}

	return formatDetails{}
}

type formatDetails struct {
	Type     string
	Version  string
	Encoding string
}

type cdxSniff struct{}

func (c cdxSniff) sniff(data []byte) formatDetails {
	stringValue := string(data)
	var format formatDetails
	if strings.Contains(stringValue, `"bomFormat"`) && strings.Contains(stringValue, `"CycloneDX"`) {
		format.Type = "application/vnd.cyclonedx"
		format.Encoding = JSON
	}

	if strings.Contains(stringValue, `"specVersion"`) {
		parts := strings.Split(stringValue, ":")
		if len(parts) == 2 {
			ver := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(parts[1]), ","), "\""), "\"")
			if ver != "" {
				format.Version = ver
				format.Encoding = JSON
			}
		}
	}

	return format
}

type spdxSniff struct{}

func (c spdxSniff) sniff(data []byte) formatDetails {
	stringValue := string(data)
	var format formatDetails

	if strings.Contains(stringValue, "SPDXVersion:") {
		format.Type = "text/spdx"
		format.Encoding = "text"

		for _, ver := range []string{"2.2", "2.3"} {
			if strings.Contains(stringValue, fmt.Sprintf("SPDX-%s", ver)) {
				format.Version = ver
				return format
			}
		}
	}

	// In JSON, the SPDX version field would be quoted
	if strings.Contains(stringValue, "\"spdxVersion\"") ||
		strings.Contains(stringValue, "'spdxVersion'") {
		format.Type = "text/spdx"
		format.Encoding = JSON
		if format.Version != "" {
			return format
		}
	}

	for _, ver := range []string{"2.2", "2.3"} {
		if strings.Contains(stringValue, fmt.Sprintf("'SPDX-%s'", ver)) ||
			strings.Contains(stringValue, fmt.Sprintf("\"SPDX-%s\"", ver)) {
			format.Version = ver
			return format
		}
	}

	return format
}
