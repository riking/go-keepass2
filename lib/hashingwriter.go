package lib

import (
	"io"
	"hash"
	"crypto/sha256"
)

type HashingWriter struct {
	w io.Writer
	hasher hash.Hash
	byteCount uint64
}

// NewHashingWriter creates a new HashingWriter over the provided io.Writer.
// If hasher is nil, sha256.New() will be used.
func NewHashingWriter(w io.Writer) *HashingWriter {
	return &HashingWriter{
		w: w,
		hasher: sha256.New(),
	}
}

func (hw *HashingWriter) Sum(in []byte) []byte {
	return hw.hasher.Sum(in)
}

func (hw *HashingWriter) Sum256() []byte {
	buf := make([]byte, sha256.Size)
	hw.hasher.Sum(buf)
	return buf
}

func (hw *HashingWriter) Write(p []byte) (n int, err error) {
	n, err = hw.w.Write(p)
	if n > 0 {
		// Re-slice to account for short writes
		hw.hasher.Write(p[:n])
	}
	hw.byteCount += n
	return
}

// ByteCount returns the number of bytes that have passed through this writer.
func (hw *HashingWriter) ByteCount() uint64 {
	return hw.byteCount
}