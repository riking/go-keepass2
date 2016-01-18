package database

import (
	"io"
	"github.com/riking/go-keepass2/lib"
	"crypto/rand"
	"fmt"
	"github.com/riking/go-keepass2/lib/kpcrypto"
	"bytes"
	"encoding/binary"
	"math"
	"crypto/sha256"
	"github.com/riking/go-keepass2/lib/kpstruct"
	"encoding/xml"
	"encoding/base64"
)

type WriteFormat int
const (
	WriteFormatEncrypted WriteFormat = iota
	WriteFormatPlain
)

const xmlHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"
const ProductName = "go-keepass2lib"

func fillRandomOrPanic(b []byte) {
	n, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	if n < len(b) {
		panic(fmt.Errorf("short read from crypto/rand.Reader, got %d out of %d bytes", n, len(b)))
	}
}

// WriteTo writes the database to the given writer stream with the default settings.
func (db *Database) WriteTo(w io.Writer) (n uint64, error) {
	return db.WriteOut(w, WriteFormatEncrypted)
}

// WriteOut writes the database to the given writer stream.
//
// File: KeePassLib/Serialization/KdbxFile.Write.cs
// Save()
func (db *Database) WriteOut(w io.Writer, format WriteFormat) (outputCounter uint64, error) {

	var masterSeed [32]byte
	var transformSeed [32]byte
	var encryptionIV [16]byte
	var protectedStreamKey [32]byte
	var streamStartBytes [32]byte

	fillRandomOrPanic(masterSeed[:])
	fillRandomOrPanic(transformSeed[:])
	fillRandomOrPanic(encryptionIV[:])
	fillRandomOrPanic(protectedStreamKey[:])
	fillRandomOrPanic(streamStartBytes[:])

	hashingWriter := lib.NewHashingWriter(w)
	defer func() {
		outputCounter = hashingWriter.ByteCount()
	}()

	var writerStream io.Writer
	var hashOfHeader [sha256.Size]byte
	var haveHashOfHeader bool
	buf := bytes.Buffer{}

	db.InnerRandomStream = StreamCipherSalsa20
	salsaStream := kpcrypto.NewSalsaRandomStream(&protectedStreamKey)

	if format == WriteFormatEncrypted {
		// WriteHeader()
		buf.Reset()
		var scratch [8]byte
		binary.LittleEndian.PutUint32(scratch[0:4], KP2Signature1)
		binary.LittleEndian.PutUint32(scratch[4:8], KP2Signature2)
		buf.Write(scratch[0:8])
		binary.LittleEndian.PutUint32(scratch[0:4], FileVersion)
		buf.Write(scratch[0:4])

		if db.CipherID != CipherUUIDAesParsed {
			panic("keepass.Database.WriteOut: Don't know how to write out any cipher other than AES")
		}
		writeHeaderField(&buf, HeaderCipherID, db.CipherID.Bytes()) // TODO - bytes might be wrong order
		binary.LittleEndian.PutUint32(scratch[0:4], uint32(db.Compression))
		writeHeaderField(&buf, HeaderCompressionFlags, scratch[0:4])
		writeHeaderField(&buf, HeaderMasterSeed, masterSeed[:])
		writeHeaderField(&buf, HeaderTransformSeed, transformSeed[:])
		binary.LittleEndian.PutUint64(scratch[0:8], db.KeyEncryptionRounds)
		writeHeaderField(&buf, HeaderTransformRounds, scratch[0:8])
		writeHeaderField(&buf, HeaderEncryptionIV, encryptionIV[:])
		writeHeaderField(&buf, HeaderProtectedStreamKey, protectedStreamKey[:])
		writeHeaderField(&buf, HeaderStreamStartBytes, streamStartBytes[:])
		// note: this was set earlier, so all newly written databases are salsa20
		binary.LittleEndian.PutUint32(scratch[0:4], uint32(db.InnerRandomStream))
		writeHeaderField(&buf, HeaderInnerRandomStreamID, scratch[0:4])
		scratch[0], scratch[1] = '\r', '\n'
		scratch[2], scratch[3] = '\r', '\n'
		writeHeaderField(&buf, HeaderEndOfHeader, scratch[0:4])


		{
			shaHash := sha256.New()
			buf.WriteTo(shaHash)
			shaHash.Sum(hashOfHeader[:0])
			haveHashOfHeader = true
		}

		_, err := buf.WriteTo(hashingWriter)
		if err != nil {
			return 0, err
		}

		// AttachStreamEncryption
		buf.Reset()
		buf.Write(masterSeed[:])
		pbInKey, err := db.MasterKey.GenerateKey32(&transformSeed, db.KeyEncryptionRounds)
		if err != nil {
			return 0, err
		}
		pbInKey.WriteTo(&buf)
		pbInKey.Clear()
		var aesKey [sha256.Size]byte
		{
			shaHash := sha256.New()
			buf.WriteTo(shaHash)
			shaHash.Sum(aesKey[:0])
		}

		// Sanitize buffer
		buf.Reset()
		buf.Write(masterSeed[:])
		buf.Write(transformSeed[:])

		writerStream = kpcrypto.NewAES256_CBC_PCKS7_Encoder(hashingWriter, aesKey, encryptionIV)
		for i, _ := range aesKey {
			aesKey[i] = 0
		}
	} else if format == WriteFormatPlain {
		writerStream = hashingWriter
	} else {
		panic("bad WriteFormat in keepass.Database.WriteOut")
	}

	// WriteDocument
	var numGroups, numEntries uint32
	numGroups, numEntries = db.Root.GetCounts(kpstruct.GetCountsRecursive)

	protBinPool := buildBinPool(db.Root)

	enc := xml.NewEncoder(writerStream)
	enc.Indent("", "\t")
	writerStream.Write([]byte(xmlHeader))
	enc.EncodeToken(startElem(xmlElemDocNode))

	// WriteMeta()
	enc.EncodeToken(startElem(xmlElemMeta))

	enc.EncodeElement(ProductName, startElem(xmlElemGenerator))
	if haveHashOfHeader {
		buf.Reset()
		b64Enc := base64.NewEncoder(base64.StdEncoding, buf)
		b64Enc.Write(hashOfHeader[:])
		b64Enc.Close()
		enc.EncodeElement(buf.String(), startElem(xmlElemHeaderHash))
	}



	enc.EncodeToken(endElem(xmlElemMeta))
	// end WriteMeta()

	enc.EncodeToken(startElem(xmlElemRoot))

	_ = salsaStream

	// TODO
	return 0, nil
}

func writeHeaderField(w io.Writer, id kdbxHeaderFieldID, data []byte) {
	l := len(data)
	if l > math.MaxUint16 {
		panic(fmt.Errorf("header field too big: got %d bytes", l))
	}

	var head [3]byte
	head[0] = byte(id)
	binary.LittleEndian.PutUint16(head[1:], uint16(l))
	w.Write(head[:])
	w.Write(data)
}

func startElem(name string) xml.StartElement {
	return xml.StartElement{Name: xml.Name{Local: name}}
}

func endElem(name string) xml.EndElement {
	return xml.EndElement{Name: xml.Name{Local: name}}
}

func encodeBool(val bool) string {
	if val {
		return "True"
	} else {
		return "False"
	}
}

func buildBinPool(root kpstruct.PasswordGroup) map[string]kpcrypto.ProtectedBuffer {
	pool := make(map[string]kpcrypto.ProtectedBuffer)
	// TODO
	return pool
}