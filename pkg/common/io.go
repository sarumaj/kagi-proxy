package common

import "io"

var _ io.ReadWriteCloser = closer{}

type closer struct {
	stream any
}

func (c closer) Close() error {
	switch w := c.stream.(type) {
	case io.Closer:
		return w.Close()

	case interface{ Close() }:
		w.Close()
	}

	return nil
}

func (c closer) Read(p []byte) (n int, err error) {
	r, ok := c.stream.(io.Reader)
	if ok {
		return r.Read(p)
	}

	return 0, io.EOF
}

func (c closer) Write(p []byte) (n int, err error) {
	w, ok := c.stream.(io.Writer)
	if ok {
		return w.Write(p)
	}

	return 0, io.ErrShortWrite
}

func Closer(o any) io.ReadWriteCloser { return closer{stream: o} }

func CloserWrap(o any, err error) (io.ReadWriteCloser, error) { return closer{stream: o}, err }
