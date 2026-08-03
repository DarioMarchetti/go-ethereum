// Copyright 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package mldsa44 implements ML-DSA-44 verification for FIPS 204 and the two
// expanded-public-key variants proposed by EIP-8051. It also provides an
// offline key-generation and signing API for the draft EIP-8051 format.
//
// The implementation is derived from Cloudflare CIRCL v1.6.4. It intentionally
// uses the generic integer implementation so consensus does not depend on cgo,
// assembly, floating point, or runtime CPU feature flags.
package mldsa44

const (
	polyDegree  = 256
	modulus     = 8380417
	qBits       = 23
	qInv        = 4236238847
	rOver256    = 41978
	droppedBits = 13

	rows              = 4
	cols              = 4
	omega             = 80
	tau               = 39
	gamma1            = 1 << 17
	gamma2            = 95232
	beta              = 78
	challengeSize     = 32
	publicKeyHashSize = 64
	expandedHashSize  = 32

	polyT1Size = polyDegree * (qBits - droppedBits) / 8
	polyZSize  = 18 * polyDegree / 8
	polyW1Size = polyDegree * (qBits - 17) / 8

	// PublicKeySize is the byte length of an encoded ML-DSA-44 public key.
	PublicKeySize = 32 + rows*polyT1Size
	// ExpandedPublicKeySize is the raw public-key size required by EIP-8051:
	// A-hat (16 polynomials), tr (32 bytes), and shifted t1 in the NTT domain
	// (4 polynomials). Polynomial coefficients are uint32 big-endian values.
	ExpandedPublicKeySize = (rows*cols*polyDegree+rows*polyDegree)*4 + expandedHashSize
	// SignatureSize is the byte length of an encoded ML-DSA-44 signature.
	SignatureSize = challengeSize + cols*polyZSize + omega + rows
)

type polynomial [polyDegree]uint32
type vectorL [cols]polynomial
type vectorK [rows]polynomial
type matrix [rows]vectorL

func reduceLe2Q(x uint32) uint32 {
	x1 := x >> 23
	x2 := x & 0x7fffff
	return x2 + (x1 << 13) - x1
}

func modQ(x uint32) uint32 {
	return le2qModQ(reduceLe2Q(x))
}

func montReduceLe2Q(x uint64) uint32 {
	m := (x * qInv) & 0xffffffff
	return uint32((x + m*uint64(modulus)) >> 32)
}

func le2qModQ(x uint32) uint32 {
	x -= modulus
	mask := uint32(int32(x) >> 31)
	return x + (mask & modulus)
}

func (p *polynomial) reduceLe2Q() {
	for i := 0; i < polyDegree; i++ {
		p[i] = reduceLe2Q(p[i])
	}
}

func (p *polynomial) normalize() {
	for i := 0; i < polyDegree; i++ {
		p[i] = modQ(p[i])
	}
}

func (p *polynomial) normalizeAssumingLe2Q() {
	for i := 0; i < polyDegree; i++ {
		p[i] = le2qModQ(p[i])
	}
}

func (p *polynomial) add(a, b *polynomial) {
	for i := 0; i < polyDegree; i++ {
		p[i] = a[i] + b[i]
	}
}

func (p *polynomial) sub(a, b *polynomial) {
	for i := 0; i < polyDegree; i++ {
		p[i] = a[i] + (2*modulus - b[i])
	}
}

func (p *polynomial) mulHat(a, b *polynomial) {
	for i := 0; i < polyDegree; i++ {
		p[i] = montReduceLe2Q(uint64(a[i]) * uint64(b[i]))
	}
}

func (p *polynomial) mulBy2toD(q *polynomial) {
	for i := 0; i < polyDegree; i++ {
		p[i] = q[i] << droppedBits
	}
}

func (p *polynomial) exceeds(bound uint32) bool {
	for i := 0; i < polyDegree; i++ {
		x := int32((modulus-1)/2) - int32(p[i])
		x ^= x >> 31
		x = int32((modulus-1)/2) - x
		if uint32(x) >= bound {
			return true
		}
	}
	return false
}

func dotHat(out *polynomial, a, b *vectorL) {
	var product polynomial
	*out = polynomial{}
	for i := 0; i < cols; i++ {
		product.mulHat(&a[i], &b[i])
		out.add(&product, out)
	}
}
