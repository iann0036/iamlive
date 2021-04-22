package faillog

import (
	"bytes"
	"io"
	"os"
)

// Logger emits content to stderr on Close() if caller panics or
// Success(false) is called.
type Logger struct {
	success bool
	buffer  bytes.Buffer
}

func (f *Logger) Close() error {
	if f.success {
		return nil
	}

	_, err := io.Copy(os.Stderr, &f.buffer)
	return err
}

func (f *Logger) Success(success bool) {
	f.success = success
}

func (f *Logger) Write(p []byte) (n int, err error) {
	return f.buffer.Write(p)
}
