package kpcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// keepassEncoder implements PCKS#7 padding on a cipher.BlockMode.
type keepassEncoder struct {
	writer   io.Writer
	blocker  cipher.BlockMode
	buffer   []byte
	stickErr error
}

func NewAES256_CBC_PCKS7_Encoder(w io.Writer, key *[32]byte, iv *[16]byte) (io.WriteCloser, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv[:])

	return keepassEncoder{writer: w, blocker: blockMode, buffer: make([]byte, 0, 2048)}
}

func (ke *keepassEncoder) Write(in []byte) (n int, err error) {
	if ke.stickErr != nil {
		return 0, ke.stickErr
	}
	inBytesRemaining := len(in)
	cur := len(ke.buffer)
	max := cap(ke.buffer)

	if cur + inBytesRemaining < max {
		newLen := cur + inBytesRemaining
		ke.buffer = ke.buffer[:newLen]
		copy(ke.buffer[cur:newLen], in)
		return len(in), nil
	}

	fillBytes := max - cur
	copy(ke.buffer[cur:max], in[:fillBytes])
	n, err = ke.flushFullBuffer()
	if err != nil {
		// getting the right # of bytes written out of here is too much work for an error case
		ke.stickErr = err
		return 0, err
	}
	inBytesRemaining -= fillBytes
	inBytesWritten := fillBytes

	for inBytesRemaining >= max {
		copy(ke.buffer[0:max], in[inBytesWritten:inBytesWritten+max])
		n, err = ke.flushFullBuffer()
		if err != nil {
			ke.stickErr = err
			return 0, err
		}
		inBytesWritten += max
		inBytesRemaining -= max
	}

	ke.buffer = ke.buffer[0:inBytesRemaining]
	copy(ke.buffer[0:inBytesRemaining], in[inBytesWritten:])
	inBytesWritten += inBytesRemaining
	if inBytesWritten != len(in) {
		panic("keepassEncoder.Write: screwed up the byte counting, code mistake")
	}

	if len(ke.buffer) == cap(ke.buffer) {
		panic("keepassEncoder.Write: screwed up the byte counting, full buffer at end of Write()")
	}
	return inBytesWritten, nil
}

func (ke *keepassEncoder) Close() error {
	if ke.stickErr {
		return ke.stickErr
	}

	// Apply PCKS#7 padding, then flush the blocks.

	bufLen := len(ke.buffer)
	bs := ke.blocker.BlockSize()
	endOfFullBlocks := int(bufLen / bs) * bs
	// Invariant: buffer is not full.
	// Therefore, we can add another block on the end if the last one is full.
	padEnd := endOfFullBlocks + bs
	if padEnd > cap(ke.buffer) {
		panic("keepassEncoder.Close: tried to put padding beyond end of buffer")
	}
	ke.buffer = ke.buffer[:padEnd]
	padContent := padEnd - bufLen
	// Apply padding
	for i := 0; i < padContent; i++ {
		ke.buffer[bufLen+i] = padContent
	}

	if ke.buffer[padEnd-1] != padContent {
		panic("keepassEncoder.Close: failed to apply PCKS7 padding")
	}

	ke.blocker.CryptBlocks(ke.buffer[:padEnd], ke.buffer[:padEnd])
	offset := 0
	for offset < padEnd {
		n, err := ke.writer.Write(ke.buffer[offset:])
		offset += n
		if err != nil {
			return err
		}
	}

	return nil
}

func (ke *keepassEncoder) flushFullBuffer() (int, error) {
	if len(ke.buffer) != cap(ke.buffer) {
		panic("keepassEncoder: incorrect flushBlocks call")
	}
	bufLen := len(ke.buffer)
	ke.blocker.CryptBlocks(ke.buffer, ke.buffer)
	offset := 0
	for offset < bufLen {
		n, err := ke.writer.Write(ke.buffer[offset:])
		offset += n
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}