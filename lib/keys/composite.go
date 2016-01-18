package keys

import "github.com/riking/go-keepass2/lib/kpcrypto"

type Composite struct {

}

func (ck *Composite) GenerateKey32(seed *[32]byte, numRounds uint64) (kpcrypto.ProtectedBuffer, error) {

	return nil, nil
}