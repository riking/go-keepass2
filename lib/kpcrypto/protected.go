package kpcrypto

import "io"

// ProtectedBuffer is a container for data that is held encrypted in memory.
// TODO implement
type ProtectedBuffer []byte

// WriteTo writes the unencrypted contents of the buffer to the provided writer.
func (pb *ProtectedBuffer) WriteTo(w io.Writer) (n uint64, err error) {
	// TODO
	return 0, nil
}

// String writes the unencrypted contents of the buffer into a string.
func (pb *ProtectedBuffer) String() string {
	return ""
}

// Clear zeroes out the buffer.
func (pb *ProtectedBuffer) Clear() {
	for i, _ := range pb {
		pb[i] = 0
	}
}