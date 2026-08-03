// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Keccak-PRNG construction follows the EIP-8051 reference implementation
// published by ZKNOX under the MIT license.

package mldsa44

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

type keccakPRNG struct {
	state   [32]byte
	counter uint64
	block   [32]byte
	offset  int
}

func newKeccakPRNG(input []byte) *keccakPRNG {
	var p keccakPRNG
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(input)
	copy(p.state[:], h.Sum(nil))
	p.offset = len(p.block)
	return &p
}

func (p *keccakPRNG) refill() {
	var input [40]byte
	copy(input[:32], p.state[:])
	binary.BigEndian.PutUint64(input[32:], p.counter)
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(input[:])
	copy(p.block[:], h.Sum(nil))
	p.counter++
	p.offset = 0
}

func (p *keccakPRNG) readByte() byte {
	if p.offset == len(p.block) {
		p.refill()
	}
	b := p.block[p.offset]
	p.offset++
	return b
}

func (p *keccakPRNG) read(out []byte) {
	for i := range out {
		out[i] = p.readByte()
	}
}

func keccakPRNGHash(out []byte, inputs ...[]byte) {
	h := sha3.NewLegacyKeccak256()
	for _, input := range inputs {
		_, _ = h.Write(input)
	}
	var state [32]byte
	copy(state[:], h.Sum(nil))
	p := keccakPRNG{state: state, offset: 32}
	p.read(out)
}
