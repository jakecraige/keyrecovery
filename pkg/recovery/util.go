package recovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"hash"
)

func leftPad(bytes []byte, targetLen int) []byte {
	if l := len(bytes); l > targetLen {
		panic(fmt.Sprintf("cannot pad to %d, bad input length: %d", targetLen, l))
	}

	// Index of where the padding stops and the content should begin
	contentStartIndex := int(targetLen) - len(bytes)

	out := make([]byte, targetLen)
	copy(out[contentStartIndex:], bytes)
	return out
}

func sha256Bytes(dat []byte) []byte {
	h := sha256.New()
	h.Write(dat)
	return h.Sum(nil)
}

func hashBytes(h hash.Hash, dat []byte) []byte {
	h.Reset()
	h.Write(dat)
	return h.Sum(nil)
}

func serializePub(pubK *ecdsa.PublicKey, byteLen int) []byte {
	pub := make([]byte, byteLen*2)
	copy(pub, leftPad(pubK.X.Bytes(), byteLen))
	copy(pub[byteLen:], leftPad(pubK.Y.Bytes(), byteLen))
	return pub
}

func byteLen(curve elliptic.Curve) int {
	// Find the nearest multiple of 8 to the bitsize we ensure the padded value is byte aligned.
	bitSize := curve.Params().BitSize
	for bitSize%8 != 0 {
		bitSize++
	}

	return bitSize / 8
}
