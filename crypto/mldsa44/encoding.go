// Copyright 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package mldsa44

func (p *polynomial) unpackT1(buf []byte) {
	j := 0
	for i := 0; i < polyT1Size; i += 5 {
		p[j] = (uint32(buf[i]) | uint32(buf[i+1])<<8) & 0x3ff
		p[j+1] = (uint32(buf[i+1]>>2) | uint32(buf[i+2])<<6) & 0x3ff
		p[j+2] = (uint32(buf[i+2]>>4) | uint32(buf[i+3])<<4) & 0x3ff
		p[j+3] = (uint32(buf[i+3]>>6) | uint32(buf[i+4])<<2) & 0x3ff
		j += 4
	}
}

func (p *polynomial) unpackZ(buf []byte) {
	j := 0
	for i := 0; i < polyZSize; i += 9 {
		p0 := uint32(buf[i]) | uint32(buf[i+1])<<8 | uint32(buf[i+2]&0x3)<<16
		p1 := uint32(buf[i+2]>>2) | uint32(buf[i+3])<<6 | uint32(buf[i+4]&0xf)<<14
		p2 := uint32(buf[i+4]>>4) | uint32(buf[i+5])<<4 | uint32(buf[i+6]&0x3f)<<12
		p3 := uint32(buf[i+6]>>6) | uint32(buf[i+7])<<2 | uint32(buf[i+8])<<10

		p0 = gamma1 - p0
		p1 = gamma1 - p1
		p2 = gamma1 - p2
		p3 = gamma1 - p3
		p0 += uint32(int32(p0)>>31) & modulus
		p1 += uint32(int32(p1)>>31) & modulus
		p2 += uint32(int32(p2)>>31) & modulus
		p3 += uint32(int32(p3)>>31) & modulus

		p[j] = p0
		p[j+1] = p1
		p[j+2] = p2
		p[j+3] = p3
		j += 4
	}
}

func (p *polynomial) packW1(buf []byte) {
	j := 0
	for i := 0; i < polyW1Size; i += 3 {
		buf[i] = byte(p[j]) | byte(p[j+1]<<6)
		buf[i+1] = byte(p[j+1]>>2) | byte(p[j+2]<<4)
		buf[i+2] = byte(p[j+2]>>4) | byte(p[j+3]<<2)
		j += 4
	}
}

func (v *vectorL) unpackZ(buf []byte) {
	offset := 0
	for i := 0; i < cols; i++ {
		v[i].unpackZ(buf[offset:])
		offset += polyZSize
	}
}

func (v *vectorL) exceeds(bound uint32) bool {
	for i := 0; i < cols; i++ {
		if v[i].exceeds(bound) {
			return true
		}
	}
	return false
}

func (v *vectorL) ntt() {
	for i := 0; i < cols; i++ {
		v[i].ntt()
	}
}

func (v *vectorK) unpackT1(buf []byte) {
	offset := 0
	for i := 0; i < rows; i++ {
		v[i].unpackT1(buf[offset:])
		offset += polyT1Size
	}
}

func (v *vectorK) unpackHint(buf []byte) bool {
	*v = vectorK{}
	previous := uint8(0)
	for i := 0; i < rows; i++ {
		end := buf[omega+i]
		if end < previous || end > omega {
			return false
		}
		for j := previous; j < end; j++ {
			if j > previous && buf[j] <= buf[j-1] {
				return false
			}
			v[i][buf[j]] = 1
		}
		previous = end
	}
	for j := previous; j < omega; j++ {
		if buf[j] != 0 {
			return false
		}
	}
	return true
}

func (v *vectorK) mulBy2toD(input *vectorK) {
	for i := 0; i < rows; i++ {
		v[i].mulBy2toD(&input[i])
	}
}

func (v *vectorK) ntt() {
	for i := 0; i < rows; i++ {
		v[i].ntt()
	}
}

func (v *vectorK) sub(a, b *vectorK) {
	for i := 0; i < rows; i++ {
		v[i].sub(&a[i], &b[i])
	}
}

func (v *vectorK) reduceLe2Q() {
	for i := 0; i < rows; i++ {
		v[i].reduceLe2Q()
	}
}

func (v *vectorK) inverseNTT() {
	for i := 0; i < rows; i++ {
		v[i].inverseNTT()
	}
}

func (v *vectorK) normalizeAssumingLe2Q() {
	for i := 0; i < rows; i++ {
		v[i].normalizeAssumingLe2Q()
	}
}

func (v *vectorK) useHint(input, hint *vectorK) {
	for i := 0; i < rows; i++ {
		useHint(&v[i], &input[i], &hint[i])
	}
}

func (v *vectorK) packW1(buf []byte) {
	offset := 0
	for i := 0; i < rows; i++ {
		v[i].packW1(buf[offset:])
		offset += polyW1Size
	}
}

func decompose(a uint32) (a0PlusQ, a1 uint32) {
	a1 = (a + 127) >> 7
	a1 = ((a1 * 11275) + (1 << 23)) >> 24
	a1 ^= uint32(int32(43-a1)>>31) & a1
	a0PlusQ = a - a1*(2*gamma2)
	a0PlusQ += uint32(int32(a0PlusQ-(modulus-1)/2)>>31) & modulus
	return a0PlusQ, a1
}

func useHint(out, input, hint *polynomial) {
	var low polynomial
	for i := 0; i < polyDegree; i++ {
		low[i], out[i] = decompose(input[i])
	}
	for i := 0; i < polyDegree; i++ {
		if hint[i] == 0 {
			continue
		}
		if low[i] > modulus {
			if out[i] == 43 {
				out[i] = 0
			} else {
				out[i]++
			}
		} else if out[i] == 0 {
			out[i] = 43
		} else {
			out[i]--
		}
	}
}
