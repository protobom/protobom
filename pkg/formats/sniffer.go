package formats

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

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
	defer func() {
		_, err := f.Seek(0, 0)
		if err != nil {
			fmt.Printf("WARNING: could not seek to beginning of file: %v", err)
		}
	}()
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)

	formatType := ""
	formatEncoding := ""
	formatVersion := ""

	for fileScanner.Scan() {
		if strings.Contains(fileScanner.Text(), `"bomFormat"`) && strings.Contains(fileScanner.Text(), `"CycloneDX"`) {
			formatType = "application/vnd.cyclonedx"
			formatEncoding = JSON
		}

		if strings.Contains(fileScanner.Text(), `"specVersion"`) {
			parts := strings.Split(fileScanner.Text(), ":")
			if len(parts) == 2 {
				ver := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(parts[1]), ","), "\""), "\"")
				if ver != "" {
					formatVersion = ver
					formatEncoding = JSON
				}
			}
		}

		if strings.Contains(fileScanner.Text(), "SPDXVersion:") {
			formatType = "text/spdx"
			formatEncoding = "text"

			for _, ver := range []string{"2.2", "2.3"} {
				if strings.Contains(fileScanner.Text(), fmt.Sprintf("SPDX-%s", ver)) {
					formatVersion = ver
					break
				}
			}
			break
		}

		// In JSON, the SPDX version field would be quoted
		if strings.Contains(fileScanner.Text(), "\"spdxVersion\"") ||
			strings.Contains(fileScanner.Text(), "'spdxVersion'") {
			formatType = "text/spdx"
			formatEncoding = JSON
			if formatVersion != "" {
				break
			}
		}

		for _, ver := range []string{"2.2", "2.3"} {
			if strings.Contains(fileScanner.Text(), fmt.Sprintf("'SPDX-%s'", ver)) ||
				strings.Contains(fileScanner.Text(), fmt.Sprintf("\"SPDX-%s\"", ver)) {
				formatVersion = ver
			}
		}
		if formatVersion != "" && formatType != "" && formatEncoding != "" {
			break
		}
	}

	for _, f := range List {
		if string(f) == fmt.Sprintf("%s+%s;version=%s", formatType, formatEncoding, formatVersion) {
			return f, nil
		}
	}

	// TODO(puerco): Implement a light parser in case the string hacks don't work
	return "", fmt.Errorf("unknown SBOM format")
}
