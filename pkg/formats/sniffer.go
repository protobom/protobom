package formats

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	stateKeySuffix = "sniffer_state"
	EmptyFormat    = Format("")
)

var sniffFormats = []sniffFormat{
	cdxSniff{},
	spdxSniff{},
}

type sniffFormat interface {
	sniff(ctx context.Context, data []byte) Format
	Type() string
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

	var format Format

	ctx := fs.setSniffState(context.Background())
	for fileScanner.Scan() {
		format = fs.sniff(ctx, fileScanner.Bytes())

		if format != EmptyFormat {
			break
		}
	}

	if format != EmptyFormat {
		return format, nil
	}

	fmt.Fprintf(
		os.Stderr, "format: %s version: %s encodingq: %s\n",
		format.Type(), format.Version(), format.Encoding(),
	)

	// TODO(puerco): Implement a light parser in case the string hacks don't work
	return "", fmt.Errorf("unknown SBOM format")
}

func (fs *Sniffer) setSniffState(ctx context.Context) context.Context {
	state := make(map[string]sniffState, len(sniffFormats))
	return setSniffState(ctx, state)
}

func (fs *Sniffer) sniff(ctx context.Context, data []byte) Format {

	for _, sniffer := range sniffFormats {
		format := sniffer.sniff(ctx, data)
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

func (c cdxSniff) Type() string {
	return "cdx"
}

func (c cdxSniff) sniff(ctx context.Context, data []byte) Format {
	state, err := getSniffState(ctx, c.Type())
	if err != nil {
		return EmptyFormat
	}

	stringValue := string(data)
	if strings.Contains(stringValue, `"bomFormat"`) && strings.Contains(stringValue, `"CycloneDX"`) {
		state.Type = "application/vnd.cyclonedx"
		state.Encoding = JSON
	}

	if strings.Contains(stringValue, `"specVersion"`) {
		parts := strings.Split(stringValue, ":")
		if len(parts) == 2 {
			ver := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(parts[1]), ","), "\""), "\"")
			if ver != "" {
				state.Version = ver
				state.Encoding = JSON
			}
		}
	}

	return state.Format()
}

type spdxSniff struct{}

func (c spdxSniff) Type() string {
	return "spdx"
}

func (c spdxSniff) sniff(ctx context.Context, data []byte) Format {
	state, err := getSniffState(ctx, c.Type())
	if err != nil {
		return EmptyFormat
	}

	stringValue := string(data)
	var format sniffState

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

	// In JSON, the SPDX version field would be quoted
	if strings.Contains(stringValue, "\"spdxVersion\"") ||
		strings.Contains(stringValue, "'spdxVersion'") {
		state.Type = "text/spdx"
		state.Encoding = JSON
		if format.Version != "" {
			return state.Format()
		}
	}

	for _, ver := range []string{"2.2", "2.3"} {
		if strings.Contains(stringValue, fmt.Sprintf("'SPDX-%s'", ver)) ||
			strings.Contains(stringValue, fmt.Sprintf("\"SPDX-%s\"", ver)) {
			state.Version = ver
			return state.Format()
		}
	}

	return state.Format()
}

func getSniffState(ctx context.Context, t string) (sniffState, error) {
	dm, ok := ctx.Value(stateKeySuffix).(map[string]sniffState)
	if !ok {
		return sniffState{}, errors.New("unable to cast serializer state from context")
	}
	return dm[t], nil
}

func setSniffState(ctx context.Context, state map[string]sniffState) context.Context {
	return context.WithValue(context.Background(), stateKeySuffix, state)
}
