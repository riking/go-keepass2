package database

import (
	"io"
	"github.com/satori/go.uuid"
	"github.com/riking/go-keepass2/lib/keys"
	"github.com/riking/go-keepass2/lib/kpstruct"
	"time"
)

type Database struct {
	Source              DBConnection

	Name string
	NameChanged time.Time
	Description string
	DescriptionChanged time.Time


	CipherID            uuid.UUID
	Compression         CompressionAlgorithmID
	KeyEncryptionRounds uint64
	InnerRandomStream   CipherRandomStreamID

	MasterKey           keys.Composite

	Root                kpstruct.PasswordGroup
}

type DBConnection interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.WriterAt
}

func New() *Database {
	// TODO
	return nil
}