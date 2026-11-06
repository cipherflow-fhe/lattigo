package clientcontext

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// MaxChunkBytes bounds all writes crossing the native or WASM sink boundary.
const MaxChunkBytes = 4 * 1024 * 1024

// Sink appends data and patches previously reserved bytes. Patch must not move
// the append cursor. An implementation must complete each write before returning.
type Sink interface {
	io.Writer
	Patch(offset uint64, data []byte) error
}

// FileSink adapts a file opened for writing. The caller owns closing, syncing,
// and publishing it; a successful serialization alone does not commit a file.
type FileSink struct {
	io.Writer
	io.WriterAt
}

func (s FileSink) Patch(offset uint64, data []byte) error {
	if offset > math.MaxInt64 || uint64(len(data)) > math.MaxInt64-offset {
		return fmt.Errorf("file patch offset exceeds int64")
	}
	n, err := s.WriteAt(data, int64(offset))
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

type streamWriter struct {
	dst Sink
	pos uint64
}

func (w *streamWriter) Write(data []byte) (int, error) {
	if uint64(len(data)) > math.MaxUint64-w.pos {
		return 0, fmt.Errorf("stream length overflows uint64")
	}
	total := 0
	for len(data) != 0 {
		chunk := data[:min(len(data), MaxChunkBytes)]
		n, err := w.dst.Write(chunk)
		if n < 0 || n > len(chunk) {
			return total, fmt.Errorf("invalid sink write count %d", n)
		}
		total += n
		w.pos += uint64(n)
		if err != nil {
			return total, err
		}
		if n != len(chunk) {
			return total, io.ErrShortWrite
		}
		data = data[n:]
	}
	return total, nil
}

func (w *streamWriter) flag(value bool) error {
	var b byte
	if value {
		b = 1
	}
	_, err := w.Write([]byte{b})
	return err
}

func (w *streamWriter) blob(write func(io.Writer) error) error {
	start := w.pos
	if _, err := w.Write(make([]byte, 8)); err != nil {
		return err
	}
	if err := write(w); err != nil {
		return err
	}
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], w.pos-start-8)
	return w.dst.Patch(start, length[:])
}

func writeObject(dst io.Writer, value io.WriterTo) error {
	// v6 WriteTo needs buffer.Writer. Flushing here makes key lifetime and sink
	// backpressure coincide, even for serializers that do not flush themselves.
	w := bufio.NewWriterSize(dst, 64*1024)
	if _, err := value.WriteTo(w); err != nil {
		return err
	}
	return w.Flush()
}
