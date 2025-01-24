package common

import "io"

var _ io.ReadWriteCloser = closer{}

type closer struct {
	stream any
}

// Implements io.Closer interface
func (c closer) Close() error {
	switch w := c.stream.(type) {
	case io.Closer:
		return w.Close()

	case interface{ Close() }:
		w.Close()

	}

	return nil
}

// Implements io.Reader interface
func (c closer) Read(p []byte) (n int, err error) {
	r, ok := c.stream.(io.Reader)
	if ok {
		return r.Read(p)
	}

	return 0, io.EOF
}

// Implements io.Writer interface
func (c closer) Write(p []byte) (n int, err error) {
	w, ok := c.stream.(io.Writer)
	if ok {
		return w.Write(p)
	}

	return 0, io.ErrShortWrite
}

// Closer builds a ReadWriteCloser interface around the given object.
func Closer(o any) io.ReadWriteCloser { return closer{stream: o} }

// CloserWrap is a convenience function that wraps the given object and error into a ReadWriteCloser interface.
// Useful to catch return values from functions that return an error.
func CloserWrap(o any, err error) (io.ReadWriteCloser, error) { return closer{stream: o}, err }
