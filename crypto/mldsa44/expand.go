// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mldsa44

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// ExpandPublicKey converts a compact ML-DSA-44 public key into the raw
// representation consumed by EIP-8051 VERIFY_MLDSA. The current draft's
// 32-byte tr and message formatting differ from the final FIPS 204 external
// interface, so signatures must be produced specifically for EIP-8051.
func ExpandPublicKey(publicKey []byte) ([]byte, bool) {
	return expandPublicKey(publicKey, false)
}

// ExpandPublicKeyETH converts a compact ML-DSA-ETH public key into the raw
// representation consumed by EIP-8051 VERIFY_MLDSA_ETH. The compact key must
// come from the Keccak-PRNG ML-DSA-ETH key-generation variant.
func ExpandPublicKeyETH(publicKey []byte) ([]byte, bool) {
	return expandPublicKey(publicKey, true)
}

func expandPublicKey(encoded []byte, eth bool) ([]byte, bool) {
	if len(encoded) != PublicKeySize {
		return nil, false
	}
	var rho [32]byte
	copy(rho[:], encoded[:32])
	var a matrix
	if eth {
		a.deriveETH(&rho)
	} else {
		a.derive(&rho)
	}

	var t1 vectorK
	t1.unpackT1(encoded[32:])
	var t1Hat vectorK
	t1Hat.mulBy2toD(&t1)
	t1Hat.ntt()
	for i := 0; i < rows; i++ {
		t1Hat[i].normalize()
	}

	var tr [expandedHashSize]byte
	if eth {
		keccakPRNGHash(tr[:], encoded)
	} else {
		h := sha3.NewShake256()
		_, _ = h.Write(encoded)
		_, _ = h.Read(tr[:])
	}

	expanded := make([]byte, ExpandedPublicKeySize)
	offset := 0
	putPolynomial := func(p *polynomial) {
		for _, coefficient := range p {
			binary.BigEndian.PutUint32(expanded[offset:offset+4], coefficient)
			offset += 4
		}
	}
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			putPolynomial(&a[i][j])
		}
	}
	copy(expanded[offset:], tr[:])
	offset += len(tr)
	for i := 0; i < rows; i++ {
		putPolynomial(&t1Hat[i])
	}
	return expanded, offset == len(expanded)
}

func (m *matrix) deriveETH(seed *[32]byte) {
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			var input [34]byte
			copy(input[:32], seed[:])
			input[32] = byte(j)
			input[33] = byte(i)
			prng := newKeccakPRNG(input[:])
			for coefficient := 0; coefficient < polyDegree; {
				candidate := (uint32(prng.readByte()) | uint32(prng.readByte())<<8 |
					uint32(prng.readByte())<<16) & 0x7fffff
				if candidate < modulus {
					m[i][j][coefficient] = candidate
					coefficient++
				}
			}
		}
	}
}
