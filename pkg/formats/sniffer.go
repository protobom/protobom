package formats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	EmptyFormat = Format("")
)

var sniffFormats = []sniffFormat{
	cdxSniff{},
	spdxSniff{},
}

var state = make(map[string]sniffState, len(sniffFormats))

type sniffFormat interface {
	sniff(data []byte) Format
}

type Sniffer struct{}

// SniffFile takes a path a return the format
func (fs *Sniffer) SniffFile(path string) (Format, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("getting info of path: %w", err)
	}
	if fileInfo.IsDir() {
		return "", fmt.Errorf("path is a directory, not a file")
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening path: %w", err)
	}
	defer f.Close()
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

	type SpecVersionStruct struct {
		BomFormat       string `json:"bomFormat"`
		CDXSpecVersion  string `json:"specVersion"`
		SPDXSpecVersion string `json:"spdxVersion"`
	}

	decoder := json.NewDecoder(f)

	var specversionjson SpecVersionStruct
	err := decoder.Decode(&specversionjson)
	if err == nil {
		if strings.EqualFold(specversionjson.BomFormat, CDXFORMAT) {
			switch specversionjson.CDXSpecVersion {
			case "1.3":
				return CDX13JSON, nil
			case "1.4":
				return CDX14JSON, nil
			case "1.5":
				return CDX15JSON, nil
			default:
				// JSON + BomFormat CycloneDX but specVersion not 1.3, 1.4, or 1.5
				return "", fmt.Errorf("unknown SBOM format")
			}
		} else {
			// JSON but not CycloneDX so assuming SPDX
			switch specversionjson.SPDXSpecVersion {
			case "SPDX-2.2":
				return SPDX22JSON, nil
			case "SPDX-2.3":
				return SPDX23JSON, nil
			default:
				// JSON + not CycloneDX but spdxVersion not SPDX-2.2 or SPDX-2.3
				return "", fmt.Errorf("unknown SBOM format")
			}
		}
	}

	// not JSON.  Parse line-by-line with string hacks

	_, err = f.Seek(0, 0)
	if err != nil {
		return "", fmt.Errorf("seeking to the beginning of SBOM file: %w", err)
	}

	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)

	var format Format

	initSniffState()
	for fileScanner.Scan() {
		format = fs.sniff(fileScanner.Bytes())

		if format != EmptyFormat {
			break
		}
	}

	if format != EmptyFormat {
		return format, nil
	}

	// TODO(puerco): Implement a light parser in case the string hacks don't work
	return "", fmt.Errorf("unknown SBOM format")
}

func (fs *Sniffer) sniff(data []byte) Format {
	for _, sniffer := range sniffFormats {
		format := sniffer.sniff(data)
		if format != EmptyFormat {
			return format
		}
	}
	return EmptyFormat
}

type sniffState struct {
	Type     string
	Version  string
	Encoding string
}

func (st *sniffState) Format() Format {
	if st.Type != "" && st.Encoding != "" && st.Version != "" {
		return Format(fmt.Sprintf("%s+%s;version=%s", st.Type, st.Encoding, st.Version))
	}

	return EmptyFormat
}

type cdxSniff struct{}

func (c cdxSniff) sniff(data []byte) Format {
	// protobom only supports CDX formats as JSON
	//  we are parsing the JSON in SniffReader by decoding to the SpecVersionStruct
	//   removing all the previous JSON-related string matching from this function
	//   if we want to support CDX XML formats in the future, could sniff for that in this func
	//   until then, return EmptyFormat because we wont get here with a supported scenario

	return EmptyFormat
}

type spdxSniff struct{}

func (c spdxSniff) sniff(data []byte) Format {
	state := getSniffState(SPDXFORMAT)

	stringValue := string(data)

	if strings.Contains(stringValue, "SPDXVersion:") {
		state.Type = "text/spdx"
		state.Encoding = "text"

		for _, ver := range []string{"2.2", "2.3"} {
			if strings.Contains(stringValue, fmt.Sprintf("SPDX-%s", ver)) {
				state.Version = ver
				return state.Format()
			}
		}
	}

	// Removed the strings.Contains to check for the JSON version
	//  JSON version should be detected above in SniffReader via json.NewDecoder()

	for _, ver := range []string{"2.2", "2.3"} {
		if strings.Contains(stringValue, fmt.Sprintf("'SPDX-%s'", ver)) ||
			strings.Contains(stringValue, fmt.Sprintf("\"SPDX-%s\"", ver)) {
			state.Version = ver
			return state.Format()
		}
	}

	setSniffState(SPDXFORMAT, state)
	return state.Format()
}

func initSniffState() {
	state = make(map[string]sniffState, len(sniffFormats))
}

func getSniffState(t string) sniffState {
	dm, ok := state[t]
	if !ok {
		state[t] = sniffState{}
		return state[t]
	}
	return dm
}

func setSniffState(t string, snifferState sniffState) {
	state[t] = snifferState
}
