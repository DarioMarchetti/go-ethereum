// Copyright 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package mldsa44

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

type publicKey struct {
	t1 vectorK
	a  matrix
	tr [publicKeyHashSize]byte
}

type expandedPublicKey struct {
	a     matrix
	tr    [expandedHashSize]byte
	t1Hat vectorK
}

type unpackedSignature struct {
	z    vectorL
	hint vectorK
	c    [challengeSize]byte
}

// Verify reports whether signature is a valid FIPS 204 ML-DSA-44 signature of
// message under publicKey. It uses the external ML-DSA interface with an empty
// context string.
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}
	pk := unpackPublicKey(publicKey)
	return verify(&pk, message, signature)
}

// VerifyExpanded reports whether signature is valid under the EIP-8051
// VERIFY_MLDSA rules. The public key must use the expanded representation
// defined by EIP-8051 and message must be exactly 32 bytes.
func VerifyExpanded(publicKey, message, signature []byte) bool {
	if len(publicKey) != ExpandedPublicKeySize || len(message) != 32 || len(signature) != SignatureSize {
		return false
	}
	pk, ok := unpackExpandedPublicKey(publicKey)
	return ok && verifyExpanded(&pk, message, signature, false)
}

// VerifyExpandedETH reports whether signature is valid under the EIP-8051
// VERIFY_MLDSA_ETH rules, which replace SHAKE256 with Keccak-PRNG.
func VerifyExpandedETH(publicKey, message, signature []byte) bool {
	if len(publicKey) != ExpandedPublicKeySize || len(message) != 32 || len(signature) != SignatureSize {
		return false
	}
	pk, ok := unpackExpandedPublicKey(publicKey)
	return ok && verifyExpanded(&pk, message, signature, true)
}

func unpackExpandedPublicKey(encoded []byte) (expandedPublicKey, bool) {
	var pk expandedPublicKey
	offset := 0
	decodePolynomial := func(p *polynomial) bool {
		for i := 0; i < polyDegree; i++ {
			coefficient := binary.BigEndian.Uint32(encoded[offset : offset+4])
			if coefficient >= modulus {
				return false
			}
			p[i] = coefficient
			offset += 4
		}
		return true
	}
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			if !decodePolynomial(&pk.a[i][j]) {
				return expandedPublicKey{}, false
			}
		}
	}
	copy(pk.tr[:], encoded[offset:offset+expandedHashSize])
	offset += expandedHashSize
	for i := 0; i < rows; i++ {
		if !decodePolynomial(&pk.t1Hat[i]) {
			return expandedPublicKey{}, false
		}
	}
	return pk, offset == len(encoded)
}

func unpackPublicKey(encoded []byte) publicKey {
	var pk publicKey
	var rho [32]byte
	copy(rho[:], encoded[:32])
	pk.t1.unpackT1(encoded[32:])
	pk.a.derive(&rho)

	h := sha3.NewShake256()
	_, _ = h.Write(encoded)
	_, _ = h.Read(pk.tr[:])
	return pk
}

func (sig *unpackedSignature) unpack(encoded []byte) bool {
	if len(encoded) != SignatureSize {
		return false
	}
	copy(sig.c[:], encoded[:challengeSize])
	sig.z.unpackZ(encoded[challengeSize:])
	if sig.z.exceeds(gamma1 - beta) {
		return false
	}
	hintOffset := challengeSize + cols*polyZSize
	return sig.hint.unpackHint(encoded[hintOffset:])
}

func verify(pk *publicKey, message, signature []byte) bool {
	var sig unpackedSignature
	if !sig.unpack(signature) {
		return false
	}

	// FIPS 204 ML-DSA.Verify prepends 0 || len(ctx) || ctx to the message.
	// The precompile fixes ctx to the empty string, hence the two zero bytes.
	var mu [64]byte
	h := sha3.NewShake256()
	_, _ = h.Write(pk.tr[:])
	_, _ = h.Write([]byte{0, 0})
	_, _ = h.Write(message)
	_, _ = h.Read(mu[:])

	zh := sig.z
	zh.ntt()
	var az vectorK
	for i := 0; i < rows; i++ {
		dotHat(&az[i], &pk.a[i], &zh)
	}

	var adjusted vectorK
	adjusted.mulBy2toD(&pk.t1)
	adjusted.ntt()
	var challenge polynomial
	deriveChallenge(&challenge, sig.c[:])
	challenge.ntt()
	for i := 0; i < rows; i++ {
		adjusted[i].mulHat(&adjusted[i], &challenge)
	}
	adjusted.sub(&az, &adjusted)
	adjusted.reduceLe2Q()
	adjusted.inverseNTT()
	adjusted.normalizeAssumingLe2Q()

	var w1 vectorK
	w1.useHint(&adjusted, &sig.hint)
	var packedW1 [polyW1Size * rows]byte
	w1.packW1(packedW1[:])

	var expected [challengeSize]byte
	h = sha3.NewShake256()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(packedW1[:])
	_, _ = h.Read(expected[:])
	return sig.c == expected
}

func verifyExpanded(pk *expandedPublicKey, message, signature []byte, eth bool) bool {
	var sig unpackedSignature
	if !sig.unpack(signature) {
		return false
	}

	var mu [64]byte
	if eth {
		keccakPRNGHash(mu[:], pk.tr[:], message)
	} else {
		h := sha3.NewShake256()
		_, _ = h.Write(pk.tr[:])
		_, _ = h.Write(message)
		_, _ = h.Read(mu[:])
	}

	zh := sig.z
	zh.ntt()
	var az vectorK
	for i := 0; i < rows; i++ {
		dotHat(&az[i], &pk.a[i], &zh)
	}

	var challenge polynomial
	if eth {
		deriveChallengeETH(&challenge, sig.c[:])
	} else {
		deriveChallenge(&challenge, sig.c[:])
	}
	challenge.ntt()
	var adjusted vectorK
	for i := 0; i < rows; i++ {
		adjusted[i].mulHat(&pk.t1Hat[i], &challenge)
	}
	adjusted.sub(&az, &adjusted)
	adjusted.reduceLe2Q()
	adjusted.inverseNTT()
	adjusted.normalizeAssumingLe2Q()

	var w1 vectorK
	w1.useHint(&adjusted, &sig.hint)
	var packedW1 [polyW1Size * rows]byte
	w1.packW1(packedW1[:])

	var expected [challengeSize]byte
	if eth {
		keccakPRNGHash(expected[:], mu[:], packedW1[:])
	} else {
		h := sha3.NewShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(packedW1[:])
		_, _ = h.Read(expected[:])
	}
	return sig.c == expected
}

func (m *matrix) derive(seed *[32]byte) {
	for i := uint16(0); i < rows; i++ {
		for j := uint16(0); j < cols; j++ {
			deriveUniform(&m[i][j], seed, (i<<8)+j)
		}
	}
}

func deriveUniform(out *polynomial, seed *[32]byte, nonce uint16) {
	var input [34]byte
	copy(input[:32], seed[:])
	input[32] = byte(nonce)
	input[33] = byte(nonce >> 8)

	h := sha3.NewShake128()
	_, _ = h.Write(input[:])
	var buf [168]byte
	index := 0
	for index < polyDegree {
		_, _ = h.Read(buf[:])
		for offset := 0; offset < len(buf) && index < polyDegree; offset += 3 {
			coefficient := (uint32(buf[offset]) | uint32(buf[offset+1])<<8 |
				uint32(buf[offset+2])<<16) & 0x7fffff
			if coefficient < modulus {
				out[index] = coefficient
				index++
			}
		}
	}
}

func deriveChallenge(out *polynomial, seed []byte) {
	var buf [136]byte
	h := sha3.NewShake256()
	_, _ = h.Write(seed)
	_, _ = h.Read(buf[:])

	signs := binary.LittleEndian.Uint64(buf[:8])
	offset := 8
	*out = polynomial{}
	for i := uint16(polyDegree - tau); i < polyDegree; i++ {
		var position uint16
		for {
			if offset >= len(buf) {
				_, _ = h.Read(buf[:])
				offset = 0
			}
			position = uint16(buf[offset])
			offset++
			if position <= i {
				break
			}
		}
		out[i] = out[position]
		out[position] = 1
		out[position] ^= uint32(-(signs & 1)) & (1 | (modulus - 1))
		signs >>= 1
	}
}

func deriveChallengeETH(out *polynomial, seed []byte) {
	prng := newKeccakPRNG(seed)
	var signBytes [8]byte
	prng.read(signBytes[:])
	signs := binary.LittleEndian.Uint64(signBytes[:])
	*out = polynomial{}
	for i := uint16(polyDegree - tau); i < polyDegree; i++ {
		var position uint16
		for {
			position = uint16(prng.readByte())
			if position <= i {
				break
			}
		}
		out[i] = out[position]
		out[position] = 1
		out[position] ^= uint32(-(signs & 1)) & (1 | (modulus - 1))
		signs >>= 1
	}
}
