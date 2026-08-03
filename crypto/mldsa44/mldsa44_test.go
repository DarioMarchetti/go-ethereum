// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mldsa44

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type testVector struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

func loadTestVector(t testing.TB) ([]byte, []byte, []byte) {
	t.Helper()
	blob, err := ioutil.ReadFile("testdata/empty-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector testVector
	if err := json.Unmarshal(blob, &vector); err != nil {
		t.Fatal(err)
	}
	decode := func(name, encoded string) []byte {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("invalid %s encoding: %v", name, err)
		}
		return value
	}
	return decode("public key", vector.PublicKey), decode("message", vector.Message), decode("signature", vector.Signature)
}

func TestVerify(t *testing.T) {
	publicKey, message, signature := loadTestVector(t)
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		t.Fatalf("unexpected vector sizes: public key %d, signature %d", len(publicKey), len(signature))
	}
	if !Verify(publicKey, message, signature) {
		t.Fatal("valid signature rejected")
	}

	tests := []struct {
		name      string
		publicKey []byte
		message   []byte
		signature []byte
	}{
		{"short public key", publicKey[:len(publicKey)-1], message, signature},
		{"long public key", append(append([]byte{}, publicKey...), 0), message, signature},
		{"short signature", publicKey, message, signature[:len(signature)-1]},
		{"long signature", publicKey, message, append(append([]byte{}, signature...), 0)},
		{"changed message", publicKey, append([]byte{1}, message...), signature},
		{"empty message", publicKey, nil, signature},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if Verify(test.publicKey, test.message, test.signature) {
				t.Fatal("invalid signature accepted")
			}
		})
	}
}

func TestVerifyRejectsModifiedEncoding(t *testing.T) {
	publicKey, message, signature := loadTestVector(t)
	tests := []struct {
		name   string
		offset int
	}{
		{"challenge", 0},
		{"z", challengeSize},
		{"hint", challengeSize + cols*polyZSize},
		{"public key seed", SignatureSize},
		{"public key t1", SignatureSize + 32},
	}
	input := append(append([]byte{}, signature...), publicKey...)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := append([]byte{}, input...)
			modified[test.offset] ^= 1
			if Verify(modified[SignatureSize:], message, modified[:SignatureSize]) {
				t.Fatal("modified encoding accepted")
			}
		})
	}
}

func TestVerifyRejectsNonCanonicalHint(t *testing.T) {
	publicKey, message, signature := loadTestVector(t)
	modified := append([]byte{}, signature...)
	hintOffset := challengeSize + cols*polyZSize
	modified[hintOffset+omega] = omega + 1
	if Verify(publicKey, message, modified) {
		t.Fatal("non-canonical hint accepted")
	}
}

func BenchmarkVerify(b *testing.B) {
	publicKey, message, signature := loadTestVector(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(publicKey, message, signature) {
			b.Fatal("valid signature rejected")
		}
	}
}

func loadEIP8051Vector(t testing.TB, variant string) ([]byte, []byte, []byte) {
	t.Helper()
	blob, err := ioutil.ReadFile("testdata/eip8051.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]testVector
	if err := json.Unmarshal(blob, &vectors); err != nil {
		t.Fatal(err)
	}
	vector, ok := vectors[variant]
	if !ok {
		t.Fatalf("missing EIP-8051 %s vector", variant)
	}
	decode := func(name, encoded string) []byte {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("invalid %s encoding: %v", name, err)
		}
		return value
	}
	compact := decode("public key", vector.PublicKey)
	return expandEIP8051PublicKey(t, compact, variant == "eth"), decode("message", vector.Message), decode("signature", vector.Signature)
}

// expandEIP8051PublicKey reproduces the offline preprocessing required by the
// EIP. Test vectors retain the compact key so the checked-in fixture stays
// small; the verifier itself only accepts the expanded representation.
func expandEIP8051PublicKey(t testing.TB, compact []byte, eth bool) []byte {
	t.Helper()
	var expanded []byte
	var ok bool
	if eth {
		expanded, ok = ExpandPublicKeyETH(compact)
	} else {
		expanded, ok = ExpandPublicKey(compact)
	}
	if !ok {
		t.Fatal("failed to expand public key")
	}
	return expanded
}

func TestVerifyExpandedEIP8051(t *testing.T) {
	for _, variant := range []string{"nist", "eth"} {
		t.Run(variant, func(t *testing.T) {
			publicKey, message, signature := loadEIP8051Vector(t, variant)
			if len(publicKey) != ExpandedPublicKeySize || len(message) != 32 || len(signature) != SignatureSize {
				t.Fatalf("unexpected vector sizes: public key %d, message %d, signature %d", len(publicKey), len(message), len(signature))
			}
			verify := VerifyExpanded
			if variant == "eth" {
				verify = VerifyExpandedETH
			}
			if !verify(publicKey, message, signature) {
				t.Fatal("valid signature rejected")
			}

			modifiedMessage := append([]byte{}, message...)
			modifiedMessage[0] ^= 1
			modifiedSignature := append([]byte{}, signature...)
			modifiedSignature[0] ^= 1
			modifiedKey := append([]byte{}, publicKey...)
			modifiedKey[len(modifiedKey)-1] ^= 1
			for _, test := range []struct {
				name      string
				publicKey []byte
				message   []byte
				signature []byte
			}{
				{"short public key", publicKey[:len(publicKey)-1], message, signature},
				{"short message", publicKey, message[:len(message)-1], signature},
				{"short signature", publicKey, message, signature[:len(signature)-1]},
				{"changed public key", modifiedKey, message, signature},
				{"changed message", publicKey, modifiedMessage, signature},
				{"changed signature", publicKey, message, modifiedSignature},
			} {
				t.Run(test.name, func(t *testing.T) {
					if verify(test.publicKey, test.message, test.signature) {
						t.Fatal("invalid input accepted")
					}
				})
			}
		})
	}
}

func TestVerifyExpandedRejectsInvalidFieldElement(t *testing.T) {
	publicKey, message, signature := loadEIP8051Vector(t, "nist")
	for _, offset := range []int{0, len(publicKey) - 4} {
		modified := append([]byte{}, publicKey...)
		binary.BigEndian.PutUint32(modified[offset:offset+4], modulus)
		if VerifyExpanded(modified, message, signature) {
			t.Fatalf("non-canonical field element accepted at offset %d", offset)
		}
	}
}

func TestSignatureRejectsNormAtBound(t *testing.T) {
	_, _, signature := loadEIP8051Vector(t, "nist")
	modified := append([]byte{}, signature...)
	modified[challengeSize] = beta
	modified[challengeSize+1] = 0
	modified[challengeSize+2] &= 0xfc
	var unpacked unpackedSignature
	if unpacked.unpack(modified) {
		t.Fatal("z coefficient at the norm bound accepted")
	}
}

func TestVerifyExpandedVariantsAreDistinct(t *testing.T) {
	nistKey, message, nistSignature := loadEIP8051Vector(t, "nist")
	ethKey, _, ethSignature := loadEIP8051Vector(t, "eth")
	if VerifyExpandedETH(nistKey, message, nistSignature) {
		t.Fatal("NIST signature accepted by ML-DSA-ETH")
	}
	if VerifyExpanded(ethKey, message, ethSignature) {
		t.Fatal("ML-DSA-ETH signature accepted by NIST ML-DSA")
	}
	if expanded, ok := ExpandPublicKey(make([]byte, PublicKeySize-1)); ok || expanded != nil {
		t.Fatal("invalid compact public key expanded")
	}
}

func TestKeccakPRNGReferenceVector(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}
	want, err := hex.DecodeString("77b7caf29d0c44ef38344ab0bec3724d4d73fcb0c022b364125a19ff674e1fea19cc6e93a06de4b0e8951a0054b4ddd5f88a35976c7a91da70770afa016347168a0c52098b6f64f1e29be2ef854813f7ce5fa7020f8f80895cf17037994d71a2")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	newKeccakPRNG(input).read(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("Keccak-PRNG output mismatch:\nhave %x\nwant %x", got, want)
	}
}

func BenchmarkVerifyExpanded(b *testing.B) {
	for _, variant := range []string{"nist", "eth"} {
		b.Run(variant, func(b *testing.B) {
			publicKey, message, signature := loadEIP8051Vector(b, variant)
			verify := VerifyExpanded
			if variant == "eth" {
				verify = VerifyExpandedETH
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !verify(publicKey, message, signature) {
					b.Fatal("valid signature rejected")
				}
			}
		})
	}
}
