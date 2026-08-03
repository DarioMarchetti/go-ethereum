// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package vm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto/mldsa44"
	"github.com/ethereum/go-ethereum/params"
)

type mldsaTestVector struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

func loadMLDSATestInput(t testing.TB, variant string) []byte {
	t.Helper()
	blob, err := ioutil.ReadFile("../../crypto/mldsa44/testdata/eip8051.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]mldsaTestVector
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
	message := decode("message", vector.Message)
	signature := decode("signature", vector.Signature)
	compactPublicKey := decode("public key", vector.PublicKey)
	var publicKey []byte
	if variant == "eth" {
		publicKey, ok = mldsa44.ExpandPublicKeyETH(compactPublicKey)
	} else {
		publicKey, ok = mldsa44.ExpandPublicKey(compactPublicKey)
	}
	if !ok {
		t.Fatal("failed to expand public key")
	}
	return append(append(message, signature...), publicKey...)
}

func TestMLDSAVerifyPrecompiles(t *testing.T) {
	for _, test := range []struct {
		name    string
		address byte
	}{
		{"nist", 0x12},
		{"eth", 0x13},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := common.BytesToAddress([]byte{test.address})
			precompile := precompiledContractsPQC[address]
			if precompile == nil {
				t.Fatalf("ML-DSA precompile is not registered at 0x%02x", test.address)
			}
			input := loadMLDSATestInput(t, test.name)
			if len(input) != mldsaVerifyInputSize {
				t.Fatalf("unexpected input size: have %d, want %d", len(input), mldsaVerifyInputSize)
			}
			if gas := precompile.RequiredGas(input); gas != params.MLDSAVerifyGas {
				t.Fatalf("unexpected gas: have %d, want %d", gas, params.MLDSAVerifyGas)
			}
			contract := NewContract(AccountRef(common.Address{}), nil, new(big.Int), params.MLDSAVerifyGas)
			output, err := RunPrecompiledContract(precompile, input, contract)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]byte, 32)
			want[31] = 1
			if !bytes.Equal(output, want) {
				t.Fatalf("unexpected verification result: %x", output)
			}
			if contract.Gas != 0 {
				t.Fatalf("gas left after verification: %d", contract.Gas)
			}
		})
	}
}

func TestMLDSAVerifyPrecompileFailures(t *testing.T) {
	valid := loadMLDSATestInput(t, "nist")
	modifiedSignature := append([]byte{}, valid...)
	modifiedSignature[32] ^= 1
	invalidField := append([]byte{}, valid...)
	publicKeyOffset := 32 + mldsa44.SignatureSize
	binary.BigEndian.PutUint32(invalidField[publicKeyOffset:publicKeyOffset+4], 8380417)
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"short", valid[:len(valid)-1]},
		{"long", append(append([]byte{}, valid...), 0)},
		{"invalid signature", modifiedSignature},
		{"invalid field element", invalidField},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := (&mldsaVerify{}).Run(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output, make([]byte, 32)) {
				t.Fatalf("invalid input returned %x", output)
			}
		})
	}

	contract := NewContract(AccountRef(common.Address{}), nil, new(big.Int), params.MLDSAVerifyGas-1)
	if _, err := RunPrecompiledContract(&mldsaVerify{}, valid, contract); err != ErrOutOfGas {
		t.Fatalf("unexpected low-gas result: %v", err)
	}
}

func TestMLDSAVerifyForkActivation(t *testing.T) {
	config := &params.ChainConfig{ChainID: big.NewInt(1), PQCForkBlock: big.NewInt(10)}
	address := common.BytesToAddress([]byte{0x12})
	input := loadMLDSATestInput(t, "nist")
	if PrecompiledContractsOsaka[address] != nil {
		t.Fatal("PQC precompile must not be activated implicitly by Osaka")
	}

	for _, test := range []struct {
		block  int64
		active bool
	}{
		{9, false},
		{10, true},
		{11, true},
	} {
		rules := config.Rules(big.NewInt(test.block))
		if rules.IsPQC != test.active {
			t.Fatalf("PQC activation at block %d: have %v, want %v", test.block, rules.IsPQC, test.active)
		}
		contract := NewContract(AccountRef(common.Address{}), nil, new(big.Int), params.MLDSAVerifyGas)
		contract.SetCallCode(&address, common.Hash{}, nil)
		evm := &EVM{chainRules: rules}
		output, err := run(evm, contract, input, false)
		if test.active {
			if err != nil || len(output) != 32 || output[31] != 1 {
				t.Fatalf("active precompile at block %d returned %x, %v", test.block, output, err)
			}
		} else if err == nil {
			t.Fatalf("precompile unexpectedly active at block %d", test.block)
		}
	}
}

func TestMLDSAVerifyOverridesLegacyPragueAddress(t *testing.T) {
	address := common.BytesToAddress([]byte{0x12})
	if PrecompiledContractsPragueFork[address] == nil {
		t.Fatal("test requires the legacy Prague BLS MapG2 precompile at 0x12")
	}
	config := &params.ChainConfig{
		ChainID:         big.NewInt(1),
		PragueForkBlock: big.NewInt(0),
		PQCForkBlock:    big.NewInt(10),
	}
	contract := NewContract(AccountRef(common.Address{}), nil, new(big.Int), params.MLDSAVerifyGas)
	contract.SetCallCode(&address, common.Hash{}, nil)
	evm := &EVM{chainRules: config.Rules(big.NewInt(10))}
	output, err := run(evm, contract, loadMLDSATestInput(t, "nist"), false)
	if err != nil || len(output) != 32 || output[31] != 1 {
		t.Fatalf("PQC overlay did not take precedence at 0x12: %x, %v", output, err)
	}
}

func TestMLDSAVerifyCallRecognition(t *testing.T) {
	address := common.BytesToAddress([]byte{0x13})
	input := loadMLDSATestInput(t, "eth")
	newEVM := func(pqcBlock *big.Int) *EVM {
		statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatal(err)
		}
		context := Context{
			CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
			Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
			BlockNumber: new(big.Int),
		}
		config := &params.ChainConfig{
			ChainID:      big.NewInt(1),
			EIP158Block:  big.NewInt(0),
			PQCForkBlock: pqcBlock,
		}
		return NewEVM(context, statedb, config, Config{})
	}

	inactive := newEVM(nil)
	if output, gas, err := inactive.Call(AccountRef(common.Address{}), address, input, params.MLDSAVerifyGas, new(big.Int)); err != nil || output != nil || gas != params.MLDSAVerifyGas {
		t.Fatalf("inactive call returned %x, gas %d, error %v", output, gas, err)
	}
	active := newEVM(big.NewInt(0))
	output, gas, err := active.Call(AccountRef(common.Address{}), address, input, params.MLDSAVerifyGas, new(big.Int))
	if err != nil || len(output) != 32 || output[31] != 1 || gas != 0 {
		t.Fatalf("active call returned %x, gas %d, error %v", output, gas, err)
	}
}

func BenchmarkMLDSAVerifyPrecompile(b *testing.B) {
	for _, variant := range []string{"nist", "eth"} {
		b.Run(variant, func(b *testing.B) {
			precompile := &mldsaVerify{eth: variant == "eth"}
			input := loadMLDSATestInput(b, variant)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				output, err := precompile.Run(input)
				if err != nil || len(output) != 32 || output[31] != 1 {
					b.Fatal("valid signature rejected")
				}
			}
		})
	}
}
