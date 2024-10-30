// package datasink exposes objects and methods to tap into the SBOM data flow
// inside of the reader and writer libraries. Interested parties can register
// listeners that can tap into SBOM data as it is being read and written to
// the main stream.
package datasink

import "io"

// Listener is the simplest datasink. It just wraps `io.Writer`. It is an
// interface that lets objects interested in tapping into the reader or writer
// IO streams. When a Listener is plugged into the reader, all the data read
// in from the reader or written from the witer will also be piped to sink's
// Write() method.
type Listener interface {
	io.Writer
}
