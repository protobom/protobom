package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"
)

//counterfeiter:generate . EntUnserializer
type EntUnserializer interface {
	Unserialize(io.Reader, *EntUnserializeOptions, any) any
}

type EntUnserializeOptions struct{}
