package writer

type WriterOption func(*Writer)

func WithConfig(config *Config) WriterOption {
	return func(w *Writer) {
		w.Config = config
	}
}

type DefaultRenderOptions struct {
	Indent int
}

type DefaultSerializeOptions struct{}

type Config struct {
	RenderOptions    interface{}
	SerializeOptions interface{}
}
