// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// EnableEIP enables the given EIP on the config.
// This operation writes in-place, and callers need to ensure that the globally
// defined jump tables are not polluted.
func EnableEIP(eipNum int, jt *JumpTable) error {
	switch eipNum {
	case 2200:
		enable2200(jt)
	case 1884:
		enable1884(jt)
	case 1344:
		enable1344(jt)
	case 2315:
		enable2315(jt)
	default:
		return fmt.Errorf("undefined eip %d", eipNum)
	}
	return nil
}

// enable1884 applies EIP-1884 to the given jump table:
// - Increase cost of BALANCE to 700
// - Increase cost of EXTCODEHASH to 700
// - Increase cost of SLOAD to 800
// - Define SELFBALANCE, with cost GasFastStep (5)
func enable1884(jt *JumpTable) {
	// Gas cost changes
	jt[SLOAD].constantGas = params.SloadGasEIP1884
	jt[BALANCE].constantGas = params.BalanceGasEIP1884
	jt[EXTCODEHASH].constantGas = params.ExtcodeHashGasEIP1884

	// New opcode
	jt[SELFBALANCE] = operation{
		execute:     opSelfBalance,
		constantGas: GasFastStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
		valid:       true,
	}
}

func opSelfBalance(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	balance := interpreter.intPool.get().Set(interpreter.evm.StateDB.GetBalance(callContext.contract.Address()))
	callContext.stack.push(balance)
	return nil, nil
}

// enable1344 applies EIP-1344 (ChainID Opcode)
// - Adds an opcode that returns the current chain’s EIP-155 unique identifier
func enable1344(jt *JumpTable) {
	// New opcode
	jt[CHAINID] = operation{
		execute:     opChainID,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
		valid:       true,
	}
}

// opChainID implements CHAINID opcode
func opChainID(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	chainId := interpreter.intPool.get().Set(interpreter.evm.chainConfig.ChainID)
	callContext.stack.push(chainId)
	return nil, nil
}

// enable2200 applies EIP-2200 (Rebalance net-metered SSTORE)
func enable2200(jt *JumpTable) {
	jt[SLOAD].constantGas = params.SloadGasEIP2200
	jt[SSTORE].dynamicGas = gasSStoreEIP2200
}

func enable2315(jt *JumpTable) {
	// // New opcode
	// jt[BEGINSUB] = operation{
	// 	execute:     opBeginSub,
	// 	constantGas: GasQuickStep,
	// 	minStack:    minStack(0, 0),
	// 	maxStack:    maxStack(0, 0),
	// 	valid:       true,
	// }
}

// enable3198 applies EIP-3198 (BASEFEE Opcode)
// - Adds an opcode that returns the current block's base fee.
func enable3198(jt *JumpTable) {
	// New opcode
	jt[BASEFEE] = operation{
		execute:     opBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
		valid:       true,
	}
}

// enable1153 applies EIP-1153 "Transient Storage"
// - Adds TLOAD that reads from transient storage
// - Adds TSTORE that writes to transient storage
func enable1153(jt *JumpTable) {
	jt[TLOAD] = operation{
		execute:     opTload,
		constantGas: params.WarmStorageReadCostEIP2929,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
		valid:       true,
	}

	jt[TSTORE] = operation{
		execute:     opTstore,
		constantGas: params.WarmStorageReadCostEIP2929,
		minStack:    minStack(2, 0),
		maxStack:    maxStack(2, 0),
		valid:       true,
	}
}

/*
	loc := common.BigToHash(callContext.stack.pop())
	val := callContext.stack.pop()
	interpreter.evm.StateDB.SetState(callContext.contract.Address(), loc, common.BigToHash(val))

	interpreter.intPool.putOne(val)
	return nil, nil

*/

// opTload implements TLOAD opcode
func opTload(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	loc := callContext.stack.peek()
	hash := common.BigToHash(loc)
	val := interpreter.evm.StateDB.GetTransientState(callContext.contract.Address(), hash)
	loc.SetBytes(val.Bytes())
	return nil, nil
}

// opTstore implements TSTORE opcode
func opTstore(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := common.BigToHash(callContext.stack.pop())
	val := common.BigToHash(callContext.stack.pop())
	interpreter.evm.StateDB.SetTransientState(callContext.contract.Address(), loc, val)
	return nil, nil
}

// opBaseFee implements BASEFEE opcode
func opBaseFee(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	callContext.stack.push(interpreter.intPool.get().SetBytes(interpreter.evm.GasPrice.Bytes()))
	return nil, nil
}

// enable3855 applies EIP-3855 (PUSH0 opcode)
func enable3855(jt *JumpTable) {
	// New opcode
	jt[PUSH0] = operation{
		execute:     opPush0,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
		valid:       true,
	}
}

// opPush0 implements the PUSH0 opcode
func opPush0(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	callContext.stack.push(interpreter.intPool.get().SetUint64(0))
	return nil, nil
}

// enable4844 applies EIP-4844 (BLOBHASH opcode)
func enable4844(jt *JumpTable) {
	jt[BLOBHASH] = operation{
		execute:     opBlobHash,
		constantGas: GasFastestStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
		valid:       true,
	}
}

// opBlobHash implements the BLOBHASH opcode
func opBlobHash(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	index := callContext.stack.peek()
	emptyHash := common.Hash{}
	index.SetBytes(emptyHash[:])
	return nil, nil
}

// enable7516 applies EIP-7516 (BLOBBASEFEE opcode)
func enable7516(jt *JumpTable) {
	jt[BLOBBASEFEE] = operation{
		execute:     opBlobBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
		valid:       true,
	}
}

// opBlobBaseFee implements BLOBBASEFEE opcode
func opBlobBaseFee(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	callContext.stack.push(interpreter.intPool.get().SetUint64(0))
	return nil, nil
}

// enable5656 enables EIP-5656 (MCOPY opcode)
// https://eips.ethereum.org/EIPS/eip-5656
func enable5656(jt *JumpTable) {
	jt[MCOPY] = operation{
		execute:     opMcopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasMcopy,
		minStack:    minStack(3, 0),
		maxStack:    maxStack(3, 0),
		memorySize:  memoryMcopy,
		valid:       true,
	}
}

// opMcopy implements the MCOPY opcode (https://eips.ethereum.org/EIPS/eip-5656)
func opMcopy(pc *uint64, interpreter *EVMInterpreter, callContext *callCtx) ([]byte, error) {
	var (
		dst    = callContext.stack.pop()
		src    = callContext.stack.pop()
		length = callContext.stack.pop()
	)
	// These values are checked for overflow during memory expansion calculation
	// (the memorySize function on the opcode).
	callContext.memory.Copy(dst.Uint64(), src.Uint64(), length.Uint64())
	return nil, nil
}
