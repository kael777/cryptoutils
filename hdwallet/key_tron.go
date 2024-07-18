package hdwallet

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const AddressLength = 21

type Address [AddressLength]byte

func (a Address) Bytes() []byte {
	return a[:]
}

func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func PubkeyToTronAddress(p ecdsa.PublicKey) Address {
	address := crypto.PubkeyToAddress(p)
	addressTron := append([]byte{0x41}, address.Bytes()...)
	return BytesToAddress(addressTron)
}

func PubkeyToAddressTron(pubKey ecdsa.PublicKey) string {
	address := crypto.PubkeyToAddress(pubKey)
	addressTron := append([]byte{0x41}, address.Bytes()...)
	return EncodeCheck(addressTron)
}

func PrikeyToAddressTron(privateKey *ecdsa.PrivateKey) string {
	return PubkeyToAddressTron(privateKey.PublicKey)
}

func TronAddressToEthAddress(addr string) string {
	x, _ := DecodeCheck(addr)
	x1 := x[1:]

	cc := common.BytesToAddress(x1)
	return strings.ToLower(cc.String())
}

func EthAddressToTronAddress(addr string) string {
	taddr := common.FromHex(addr)
	// addressTron := append([]byte{0x41}, []byte(addr)...)
	return EncodeCheck(taddr)
}
