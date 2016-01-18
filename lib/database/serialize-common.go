package database

import "github.com/satori/go.uuid"

// File: KeePassLib/Serialization/KdbxFile.cs
// constants
const (
	KP2Signature1 = 0x9AA2D903
	KP2Signature2 = 0xB54BFB67
	KP1Signature1 = 0x9AA2D903
	KP1Signature2 = 0xB54BFB65
	KP2AlphaSignature1 = 0x9AA2D903
	KP2AlphaSignature2 = 0xB54BFB66

// FileVersion is the current kdbx format version.
// High two bytes are critical, low two bytes are informational.
// See KeePass source for more info...
	FileVersion = 0x00030001
	FileVersionCriticalMask = 0xFFFF0000
)

// kdbxHeaderFieldID identifies the type of the header field.
//
// File: KeePassLib/Serialization/KdbxFile.cs
// enum KdbxHeaderFieldID
type kdbxHeaderFieldID byte

const (
	HeaderEndOfHeader kdbxHeaderFieldID = iota
	HeaderComment
	HeaderCipherID
	HeaderCompressionFlags
	HeaderMasterSeed
	HeaderTransformSeed
	HeaderTransformRounds
	HeaderEncryptionIV
	HeaderProtectedStreamKey
	HeaderStreamStartBytes
	HeaderInnerRandomStreamID
)

// CompressionAlgorithmID identifies the database compression.
//
// File: KeePassLib/PwEnums.cs
// PwCompressionAlgorithm
type CompressionAlgorithmID uint32

const (
	CompressionNone CompressionAlgorithmID = iota
	CompressionGzip
	CompressionInvalid
)

// CipherRandomStreamID identifies the type of cipher stream in use.
//
// file: KeePassLib/Cryptography/CryptoRandomStream.cs
// CrsAlgorithm
type CipherRandomStreamID uint32

const (
	StreamCipherNone CipherRandomStreamID = iota
	StreamCipherArcFourVariant
	StreamCipherSalsa20
	StreamCipherInvalid
)

// CipherUUIDAES is the identifier for standard AES.
//
// file: KeePassLib/Cryptography/Cipher/StandardAesEngine.cs
// AesUuid
const (
	CipherUUIDAES = []byte{0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF}
)

var CipherUUIDAesParsed = uuid.FromBytesOrNil(CipherUUIDAES)

// XML element names.
//
// File: KeePassLib/Serialization/KdbxFile.cs
// ElemDocNode and friends
const (
	xmlElemDocNode = "KeePassFile"
	xmlElemMeta = "Meta"
	xmlElemRoot = "Root"
	xmlElemGroup = "Group"
	xmlElemEntry = "Entry"

	xmlElemGenerator = "Generator"
	xmlElemHeaderHash = "HeaderHash"
	xmlElemDbName = "DatabaseName"
	xmlElemDbNameChanged = "DatabaseNameChanged"
	xmlElemDbDesc = "DatabaseDescription"
	xmlElemDbDescChanged = "DatabaseDescriptionChanged"
	xmlElemDbDefaultUser = "DefaultUserName"
	xmlElemDbDefaultUserChanged = "DefaultUserNameChanged"
	xmlElemDbMntncHistoryDays = "MaintenanceHistoryDays"
	xmlElemDbColor = "Color"
	xmlElemDbKeyChanged = "MasterKeyChanged"
	xmlElemDbKeyChangeRec = "MasterKeyChangeRec"
	xmlElemDbKeyChangeForce = "MasterKeyChangeForce"
	xmlElemRecycleBinEnabled = "RecycleBinEnabled"
	xmlElemRecycleBinUuid = "RecycleBinUUID"
	xmlElemRecycleBinChanged = "RecycleBinChanged"
	xmlElemEntryTemplatesGroup = "EntryTemplatesGroup"
	xmlElemEntryTemplatesGroupChanged = "EntryTemplatesGroupChanged"
	xmlElemHistoryMaxItems = "HistoryMaxItems"
	xmlElemHistoryMaxSize = "HistoryMaxSize"
	xmlElemLastSelectedGroup = "LastSelectedGroup"
	xmlElemLastTopVisibleGroup = "LastTopVisibleGroup"
)
