// Package kpcrypto provides cryptography primitives for KeePass.
package kpcrypto

import (
	"encoding/binary"
	"crypto/sha256"
)

// SalsaRandomStream is a predictable byte-stream.
//
// file: KeePassLib/Cryptography/CryptoRandomStream.cs
type SalsaRandomStream struct {
	Salsa20Cipher
}

// Salsa20Cipher implements the Salsa20 cipher.
//
// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// m_state, m_output, m_outputPos
type Salsa20Cipher struct {
	state [16]uint32
	output [64]byte
	outputPos int
}

// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// Salsa20Cipher.m_sigma
const (
	s20_sigma1 = 0x61707865
	s20_sigma2 = 0x3320646E
	s20_sigma3 = 0x79622D32
	s20_sigma4 = 0x6B206574
)

// NewSalsa20Cipher initializes the state of the Salsa20 cipher.
//
// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// constructor, KeySetup(), IVSetup()
// The state[] assignments have been rearranged for your reading pleasure.
func NewSalsa20Cipher(key *[32]byte, iv *[8]byte, dest *Salsa20Cipher) *Salsa20Cipher {
	c := dest
	if c == nil {
		c = new(Salsa20Cipher)
	}
	c.state[0] = s20_sigma1
	c.state[1] = binary.LittleEndian.Uint32(key[0:])
	c.state[2] = binary.LittleEndian.Uint32(key[4:])
	c.state[3] = binary.LittleEndian.Uint32(key[8:])
	c.state[4] = binary.LittleEndian.Uint32(key[12:])
	c.state[5] = s20_sigma2
	c.state[6] = binary.LittleEndian.Uint32(iv[0:])
	c.state[7] = binary.LittleEndian.Uint32(iv[4:])
	c.state[8] = 0
	c.state[9] = 0
	c.state[10] = s20_sigma3
	c.state[11] = binary.LittleEndian.Uint32(key[16:])
	c.state[12] = binary.LittleEndian.Uint32(key[20:])
	c.state[13] = binary.LittleEndian.Uint32(key[24:])
	c.state[14] = binary.LittleEndian.Uint32(key[28:])
	c.state[15] = s20_sigma4
	return c
}

// Next() cycles the cipher state.
//
// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// NextOutput()
func (s20 *Salsa20Cipher) next() {
	var scratch [16]uint32
	copy(scratch[:], s20.state[:])

	for i := 0; i < 10; i++ {
		scratch[ 4] ^= rotl32(scratch[ 0] + scratch[12],  7);
		scratch[ 8] ^= rotl32(scratch[ 4] + scratch[ 0],  9);
		scratch[12] ^= rotl32(scratch[ 8] + scratch[ 4], 13);
		scratch[ 0] ^= rotl32(scratch[12] + scratch[ 8], 18);
		scratch[ 9] ^= rotl32(scratch[ 5] + scratch[ 1],  7);
		scratch[13] ^= rotl32(scratch[ 9] + scratch[ 5],  9);
		scratch[ 1] ^= rotl32(scratch[13] + scratch[ 9], 13);
		scratch[ 5] ^= rotl32(scratch[ 1] + scratch[13], 18);
		scratch[14] ^= rotl32(scratch[10] + scratch[ 6],  7);
		scratch[ 2] ^= rotl32(scratch[14] + scratch[10],  9);
		scratch[ 6] ^= rotl32(scratch[ 2] + scratch[14], 13);
		scratch[10] ^= rotl32(scratch[ 6] + scratch[ 2], 18);
		scratch[ 3] ^= rotl32(scratch[15] + scratch[11],  7);
		scratch[ 7] ^= rotl32(scratch[ 3] + scratch[15],  9);
		scratch[11] ^= rotl32(scratch[ 7] + scratch[ 3], 13);
		scratch[15] ^= rotl32(scratch[11] + scratch[ 7], 18);
		scratch[ 1] ^= rotl32(scratch[ 0] + scratch[ 3],  7);
		scratch[ 2] ^= rotl32(scratch[ 1] + scratch[ 0],  9);
		scratch[ 3] ^= rotl32(scratch[ 2] + scratch[ 1], 13);
		scratch[ 0] ^= rotl32(scratch[ 3] + scratch[ 2], 18);
		scratch[ 6] ^= rotl32(scratch[ 5] + scratch[ 4],  7);
		scratch[ 7] ^= rotl32(scratch[ 6] + scratch[ 5],  9);
		scratch[ 4] ^= rotl32(scratch[ 7] + scratch[ 6], 13);
		scratch[ 5] ^= rotl32(scratch[ 4] + scratch[ 7], 18);
		scratch[11] ^= rotl32(scratch[10] + scratch[ 9],  7);
		scratch[ 8] ^= rotl32(scratch[11] + scratch[10],  9);
		scratch[ 9] ^= rotl32(scratch[ 8] + scratch[11], 13);
		scratch[10] ^= rotl32(scratch[ 9] + scratch[ 8], 18);
		scratch[12] ^= rotl32(scratch[15] + scratch[14],  7);
		scratch[13] ^= rotl32(scratch[12] + scratch[15],  9);
		scratch[14] ^= rotl32(scratch[13] + scratch[12], 13);
		scratch[15] ^= rotl32(scratch[14] + scratch[13], 18);
	}

	for i, v := range s20.state {
		scratch[i] += v
	}

	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(s20.output[i << 2:], scratch[i])
	}

	for i, _ := range scratch {
		scratch[i] = 0
	}

	s20.outputPos = 0

	s20.state[8]++
	if s20.state[8] == 0 {
		s20.state[9]++
	}
}

// rotl32 executes a roll-left operation.
//
// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// Rotl32()
func rotl32(x uint32, count uint) uint32 {
	return (x << count) | (x >> (32 - count))
}

// Cipher retrieves bytes from the deterministic cipher.
// If xor is true, it will xor the stream bytes into the provided slice.
// If xor is false, it will copy the stream bytes into the provided slice.
//
// file: KeePassLib/Cryptography/CryptoRandomStream.cs
// GetRandomBytes()
// file: KeePassLib/Cryptography/Cipher/Salsa20Cipher.cs
// Encrypt()
func (s20 *Salsa20Cipher) Cipher(p []byte, xor bool) {
	count := len(p)

	var bytesRemaining, outputOffset int
	bytesRemaining = count

	for bytesRemaining > 0 {
		if s20.outputPos == 64 {
			s20.next()
		}
		if s20.outputPos >= 64 {
			panic("incorrect code in SalsaRandomStream.Read")
		}

		nCopy := 64 - s20.outputPos
		if bytesRemaining < nCopy {
			nCopy = bytesRemaining
		}

		if xor {
			// the length performed is the shorter of the latter 2 slices
			xorBytes(p[outputOffset:], p[outputOffset:outputOffset+nCopy], s20.output[s20.outputPos:64])
		} else {
			copy(p[outputOffset:], s20.output[s20.outputPos:])
		}

		s20.outputPos += nCopy
		outputOffset += nCopy
		bytesRemaining -= nCopy
	}
}

// file: KeePassLib/Cryptography/CryptoRandomStream.cs
// constructor, byte[] pbIV
const (
	srs_iv_0 = 0xE8
	srs_iv_1 = 0x30
	srs_iv_2 = 0x09
	srs_iv_3 = 0x4B
	srs_iv_4 = 0x97
	srs_iv_5 = 0x20
	srs_iv_6 = 0x5D
	srs_iv_7 = 0x2A
)

// NewSalsaRandomStream sets up a SalsaRandomStream using the given key.
//
// file: KeePassLib/Cryptography/CryptoRandomStream.cs
// constructor
func NewSalsaRandomStream(key *[32]byte) *SalsaRandomStream {
	var salsaKey [32]byte = sha256.Sum256(key[:])
	var salsaIV [8]byte = [8]byte{srs_iv_0, srs_iv_1, srs_iv_2, srs_iv_3, srs_iv_4, srs_iv_5, srs_iv_6, srs_iv_7}

	rs := &SalsaRandomStream{}
	NewSalsa20Cipher(&salsaKey, &salsaIV, &rs.Salsa20Cipher)
	return rs
}

// Read gets deterministic bytes from the backing Salsa20 cipher.
// This method always completes a full read and never errors.
//
// file: KeePassLib/Cryptography/CryptoRandomStream.cs
// GetRandomBytes()
func (rs *SalsaRandomStream) Read(p []byte) (nn int, err error) {
	rs.Salsa20Cipher.Cipher(p, false)
	return len(p), nil
}