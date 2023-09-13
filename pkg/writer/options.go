package writer

type WriterOption func(*Writer)

func WithConfig(config *Config) WriterOption {
	return func(w *Writer) {
		w.Config = config
	}
}

type Config struct {
	Indent int
}
