// Copyright 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package mldsa44

import (
	cryptoRand "crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// EIP8051SeedSize is the size of the private seed used to derive an
	// EIP-8051 ML-DSA-44 key pair.
	EIP8051SeedSize = 32
	eta             = 2
	maxSignAttempts = 576
)

// EIP8051Variant identifies one of the two ML-DSA variants in EIP-8051.
type EIP8051Variant uint8

const (
	// EIP8051MLDSA is the SHAKE-based VERIFY_MLDSA variant at address 0x12.
	EIP8051MLDSA EIP8051Variant = iota
	// EIP8051MLDSAETH is the Keccak-PRNG VERIFY_MLDSA_ETH variant at address 0x13.
	EIP8051MLDSAETH
)

// EIP8051PrivateKey is an in-memory signing key for the draft EIP-8051
// message format. It is deliberately separate from the FIPS 204 external
// interface because the current EIP uses a 32-byte tr and no context prefix.
type EIP8051PrivateKey struct {
	variant   EIP8051Variant
	seed      [EIP8051SeedSize]byte
	key       [32]byte
	tr        [expandedHashSize]byte
	publicKey [PublicKeySize]byte
	a         matrix
	s1Hat     vectorL
	s2Hat     vectorK
	t0Hat     vectorK
}

// GenerateEIP8051Key creates a fresh EIP-8051 key pair. The compact public
// key is safe to share; the returned private key and its seed must stay secret.
func GenerateEIP8051Key(random io.Reader, variant EIP8051Variant) ([]byte, *EIP8051PrivateKey, error) {
	if random == nil {
		random = cryptoRand.Reader
	}
	var seed [EIP8051SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, nil, fmt.Errorf("read ML-DSA seed: %w", err)
	}
	return NewEIP8051KeyFromSeed(&seed, variant)
}

// NewEIP8051KeyFromSeed deterministically derives an EIP-8051 key pair from
// a 32-byte private seed. It is useful for persistent wallets and test vectors.
func NewEIP8051KeyFromSeed(seed *[EIP8051SeedSize]byte, variant EIP8051Variant) ([]byte, *EIP8051PrivateKey, error) {
	if seed == nil {
		return nil, nil, errors.New("ML-DSA seed is nil")
	}
	if !variant.valid() {
		return nil, nil, fmt.Errorf("unsupported EIP-8051 variant %d", variant)
	}

	var expandedSeed [128]byte
	var seedInput [EIP8051SeedSize + 2]byte
	copy(seedInput[:], seed[:])
	seedInput[EIP8051SeedSize] = rows
	seedInput[EIP8051SeedSize+1] = cols
	eip8051Hash(variant, expandedSeed[:], seedInput[:])

	var rho [32]byte
	var secretSeed [64]byte
	copy(rho[:], expandedSeed[:32])
	copy(secretSeed[:], expandedSeed[32:96])

	sk := &EIP8051PrivateKey{variant: variant, seed: *seed}
	copy(sk.key[:], expandedSeed[96:])
	if variant == EIP8051MLDSAETH {
		sk.a.deriveETH(&rho)
	} else {
		sk.a.derive(&rho)
	}

	var s1 vectorL
	var s2 vectorK
	for i := 0; i < cols; i++ {
		deriveUniformLeqEta(&s1[i], secretSeed[:], uint16(i), variant)
	}
	for i := 0; i < rows; i++ {
		deriveUniformLeqEta(&s2[i], secretSeed[:], uint16(cols+i), variant)
	}

	sk.s1Hat = s1
	sk.s1Hat.ntt()
	sk.s2Hat = s2
	sk.s2Hat.ntt()

	var t vectorK
	for i := 0; i < rows; i++ {
		dotHat(&t[i], &sk.a[i], &sk.s1Hat)
		t[i].reduceLe2Q()
		t[i].inverseNTT()
	}
	t.add(&t, &s2)
	t.normalize()

	var t0, t1 vectorK
	t.power2Round(&t0, &t1)
	sk.t0Hat = t0
	sk.t0Hat.ntt()

	copy(sk.publicKey[:32], rho[:])
	t1.packT1(sk.publicKey[32:])
	eip8051Hash(variant, sk.tr[:], sk.publicKey[:])
	return sk.PublicKey(), sk, nil
}

// PublicKey returns a copy of the compact 1,312-byte public key.
func (sk *EIP8051PrivateKey) PublicKey() []byte {
	if sk == nil {
		return nil
	}
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, sk.publicKey[:])
	return publicKey
}

// Seed returns a copy of the private 32-byte key seed. Callers must protect
// this value like any other private key material.
func (sk *EIP8051PrivateKey) Seed() []byte {
	if sk == nil {
		return nil
	}
	seed := make([]byte, EIP8051SeedSize)
	copy(seed, sk.seed[:])
	return seed
}

// SignEIP8051 signs a 32-byte EIP-8051 message using fresh 32-byte
// randomization. Passing nil uses crypto/rand.Reader.
func SignEIP8051(sk *EIP8051PrivateKey, message []byte, random io.Reader) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("ML-DSA private key is nil")
	}
	if len(message) != 32 {
		return nil, fmt.Errorf("EIP-8051 message must be 32 bytes, got %d", len(message))
	}
	if !sk.variant.valid() {
		return nil, fmt.Errorf("unsupported EIP-8051 variant %d", sk.variant)
	}
	if random == nil {
		random = cryptoRand.Reader
	}
	var rnd [32]byte
	if _, err := io.ReadFull(random, rnd[:]); err != nil {
		return nil, fmt.Errorf("read ML-DSA signing randomness: %w", err)
	}

	var mu, rhoPrime [64]byte
	eip8051Hash(sk.variant, mu[:], sk.tr[:], message)
	eip8051Hash(sk.variant, rhoPrime[:], sk.key[:], rnd[:], mu[:])

	var yNonce uint16
	for attempt := 0; attempt < maxSignAttempts; attempt++ {
		var y, yHat, z vectorL
		for i := 0; i < cols; i++ {
			deriveUniformLeGamma1(&y[i], rhoPrime[:], yNonce+uint16(i), sk.variant)
		}
		yNonce += cols

		yHat = y
		yHat.ntt()
		var w vectorK
		for i := 0; i < rows; i++ {
			dotHat(&w[i], &sk.a[i], &yHat)
			w[i].reduceLe2Q()
			w[i].inverseNTT()
		}
		w.normalizeAssumingLe2Q()

		var w0, w1 vectorK
		w.decompose(&w0, &w1)
		var packedW1 [polyW1Size * rows]byte
		w1.packW1(packedW1[:])
		var challengeSeed [challengeSize]byte
		eip8051Hash(sk.variant, challengeSeed[:], mu[:], packedW1[:])

		var challenge polynomial
		if sk.variant == EIP8051MLDSAETH {
			deriveChallengeETH(&challenge, challengeSeed[:])
		} else {
			deriveChallenge(&challenge, challengeSeed[:])
		}
		challenge.ntt()

		var w0MinusCS2 vectorK
		for i := 0; i < rows; i++ {
			w0MinusCS2[i].mulHat(&challenge, &sk.s2Hat[i])
			w0MinusCS2[i].inverseNTT()
		}
		w0MinusCS2.sub(&w0, &w0MinusCS2)
		w0MinusCS2.normalize()
		if w0MinusCS2.exceeds(gamma2 - beta) {
			continue
		}

		for i := 0; i < cols; i++ {
			z[i].mulHat(&challenge, &sk.s1Hat[i])
			z[i].inverseNTT()
		}
		z.add(&z, &y)
		z.normalize()
		if z.exceeds(gamma1 - beta) {
			continue
		}

		var cT0 vectorK
		for i := 0; i < rows; i++ {
			cT0[i].mulHat(&challenge, &sk.t0Hat[i])
			cT0[i].inverseNTT()
		}
		cT0.normalizeAssumingLe2Q()
		if cT0.exceeds(gamma2) {
			continue
		}

		var hintInput, hint vectorK
		hintInput.add(&w0MinusCS2, &cT0)
		hintInput.normalizeAssumingLe2Q()
		if hint.makeHint(&hintInput, &w1) > omega {
			continue
		}

		signature := make([]byte, SignatureSize)
		copy(signature[:challengeSize], challengeSeed[:])
		z.packZ(signature[challengeSize:])
		hint.packHint(signature[challengeSize+cols*polyZSize:])
		return signature, nil
	}
	return nil, errors.New("ML-DSA signing rejection limit exceeded")
}

func (variant EIP8051Variant) valid() bool {
	return variant == EIP8051MLDSA || variant == EIP8051MLDSAETH
}

type eip8051XOF interface {
	read([]byte)
}

type shake256XOF struct {
	hash sha3.ShakeHash
}

func (x *shake256XOF) read(out []byte) {
	_, _ = x.hash.Read(out)
}

func newEIP8051XOF(variant EIP8051Variant, inputs ...[]byte) eip8051XOF {
	if variant == EIP8051MLDSAETH {
		length := 0
		for _, input := range inputs {
			length += len(input)
		}
		seed := make([]byte, 0, length)
		for _, input := range inputs {
			seed = append(seed, input...)
		}
		return newKeccakPRNG(seed)
	}
	h := sha3.NewShake256()
	for _, input := range inputs {
		_, _ = h.Write(input)
	}
	return &shake256XOF{hash: h}
}

func eip8051Hash(variant EIP8051Variant, out []byte, inputs ...[]byte) {
	newEIP8051XOF(variant, inputs...).read(out)
}

func deriveUniformLeqEta(out *polynomial, seed []byte, nonce uint16, variant EIP8051Variant) {
	var nonceBytes [2]byte
	nonceBytes[0] = byte(nonce)
	nonceBytes[1] = byte(nonce >> 8)
	xof := newEIP8051XOF(variant, seed, nonceBytes[:])
	index := 0
	var buf [136]byte
	for index < polyDegree {
		xof.read(buf[:])
		for _, value := range buf {
			for _, candidate := range [...]uint32{uint32(value & 0x0f), uint32(value >> 4)} {
				if candidate <= 14 {
					candidate -= ((205 * candidate) >> 10) * 5
					out[index] = modulus + eta - candidate
					index++
					if index == polyDegree {
						return
					}
				}
			}
		}
	}
}

func deriveUniformLeGamma1(out *polynomial, seed []byte, nonce uint16, variant EIP8051Variant) {
	var nonceBytes [2]byte
	nonceBytes[0] = byte(nonce)
	nonceBytes[1] = byte(nonce >> 8)
	var packed [polyZSize]byte
	eip8051Hash(variant, packed[:], seed, nonceBytes[:])
	out.unpackZ(packed[:])
}

func power2Round(a uint32) (a0PlusQ, a1 uint32) {
	a0 := a & ((1 << droppedBits) - 1)
	a0 -= (1 << (droppedBits - 1)) + 1
	a0 += uint32(int32(a0)>>31) & (1 << droppedBits)
	a0 -= (1 << (droppedBits - 1)) - 1
	return modulus + a0, (a - a0) >> droppedBits
}

func makeHint(z0, r1 uint32) uint32 {
	if z0 <= gamma2 || z0 > modulus-gamma2 || (z0 == modulus-gamma2 && r1 == 0) {
		return 0
	}
	return 1
}

func (p *polynomial) power2Round(p0, p1 *polynomial) {
	for i := 0; i < polyDegree; i++ {
		p0[i], p1[i] = power2Round(p[i])
	}
}

func (p *polynomial) packT1(buf []byte) {
	index := 0
	for offset := 0; offset < polyT1Size; offset += 5 {
		buf[offset] = byte(p[index])
		buf[offset+1] = byte(p[index]>>8) | byte(p[index+1]<<2)
		buf[offset+2] = byte(p[index+1]>>6) | byte(p[index+2]<<4)
		buf[offset+3] = byte(p[index+2]>>4) | byte(p[index+3]<<6)
		buf[offset+4] = byte(p[index+3] >> 2)
		index += 4
	}
}

func (p *polynomial) packZ(buf []byte) {
	index := 0
	for offset := 0; offset < polyZSize; offset += 9 {
		p0 := gamma1 - p[index]
		p0 += uint32(int32(p0)>>31) & modulus
		p1 := gamma1 - p[index+1]
		p1 += uint32(int32(p1)>>31) & modulus
		p2 := gamma1 - p[index+2]
		p2 += uint32(int32(p2)>>31) & modulus
		p3 := gamma1 - p[index+3]
		p3 += uint32(int32(p3)>>31) & modulus

		buf[offset] = byte(p0)
		buf[offset+1] = byte(p0 >> 8)
		buf[offset+2] = byte(p0>>16) | byte(p1<<2)
		buf[offset+3] = byte(p1 >> 6)
		buf[offset+4] = byte(p1>>14) | byte(p2<<4)
		buf[offset+5] = byte(p2 >> 4)
		buf[offset+6] = byte(p2>>12) | byte(p3<<6)
		buf[offset+7] = byte(p3 >> 2)
		buf[offset+8] = byte(p3 >> 10)
		index += 4
	}
}

func (v *vectorL) add(a, b *vectorL) {
	for i := 0; i < cols; i++ {
		v[i].add(&a[i], &b[i])
	}
}

func (v *vectorL) normalize() {
	for i := 0; i < cols; i++ {
		v[i].normalize()
	}
}

func (v *vectorL) packZ(buf []byte) {
	offset := 0
	for i := 0; i < cols; i++ {
		v[i].packZ(buf[offset:])
		offset += polyZSize
	}
}

func (v *vectorK) add(a, b *vectorK) {
	for i := 0; i < rows; i++ {
		v[i].add(&a[i], &b[i])
	}
}

func (v *vectorK) normalize() {
	for i := 0; i < rows; i++ {
		v[i].normalize()
	}
}

func (v *vectorK) exceeds(bound uint32) bool {
	for i := 0; i < rows; i++ {
		if v[i].exceeds(bound) {
			return true
		}
	}
	return false
}

func (v *vectorK) power2Round(v0, v1 *vectorK) {
	for i := 0; i < rows; i++ {
		v[i].power2Round(&v0[i], &v1[i])
	}
}

func (v *vectorK) decompose(v0, v1 *vectorK) {
	for i := 0; i < rows; i++ {
		for j := 0; j < polyDegree; j++ {
			v0[i][j], v1[i][j] = decompose(v[i][j])
		}
	}
}

func (v *vectorK) makeHint(v0, v1 *vectorK) (population uint32) {
	for i := 0; i < rows; i++ {
		for j := 0; j < polyDegree; j++ {
			v[i][j] = makeHint(v0[i][j], v1[i][j])
			population += v[i][j]
		}
	}
	return population
}

func (v *vectorK) packT1(buf []byte) {
	offset := 0
	for i := 0; i < rows; i++ {
		v[i].packT1(buf[offset:])
		offset += polyT1Size
	}
}

func (v *vectorK) packHint(buf []byte) {
	offset := uint8(0)
	for i := 0; i < rows; i++ {
		for j := 0; j < polyDegree; j++ {
			if v[i][j] != 0 {
				buf[offset] = byte(j)
				offset++
			}
		}
		buf[omega+i] = offset
	}
	for ; offset < omega; offset++ {
		buf[offset] = 0
	}
}
