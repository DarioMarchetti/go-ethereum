// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Backported from upstream v1.9.22 to support consumers (e.g. mova-chain-syncnode
// chain/trie) that rely on these accessors. The functions intentionally mirror
// the upstream behaviour for the trie/code namespaces.

package rawdb

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// codePrefix is the leveldb key prefix used to namespace contract code values
// when they are stored under the "current" scheme.  When code is written
// without the prefix (the legacy scheme) the raw code hash is used as the key.
var codePrefix = []byte("c")

// codeKey returns the namespaced key for a contract code blob.
func codeKey(hash common.Hash) []byte {
	return append(codePrefix, hash.Bytes()...)
}

// IsCodeKey reports whether the given key encodes a contract code value under
// the current namespaced scheme, returning the embedded code hash bytes.
func IsCodeKey(key []byte) (bool, []byte) {
	if bytes.HasPrefix(key, codePrefix) && len(key) == common.HashLength+len(codePrefix) {
		return true, key[len(codePrefix):]
	}
	return false, nil
}

// ReadCode retrieves the contract code of the provided code hash. It tries
// the legacy scheme first, falling back to the namespaced scheme.
func ReadCode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(hash[:])
	if len(data) != 0 {
		return data
	}
	return ReadCodeWithPrefix(db, hash)
}

// ReadCodeWithPrefix retrieves the contract code stored under the namespaced
// scheme only.
func ReadCodeWithPrefix(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(codeKey(hash))
	return data
}

// WriteCode writes the provided contract code to the database under the
// namespaced scheme.
func WriteCode(db ethdb.KeyValueWriter, hash common.Hash, code []byte) {
	if err := db.Put(codeKey(hash), code); err != nil {
		log.Crit("Failed to store contract code", "err", err)
	}
}

// DeleteCode deletes the specified contract code from the database.
func DeleteCode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(codeKey(hash)); err != nil {
		log.Crit("Failed to delete contract code", "err", err)
	}
}

// ReadTrieNode retrieves the trie node of the provided hash.
func ReadTrieNode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(hash.Bytes())
	return data
}

// WriteTrieNode writes the provided trie node into the database.
func WriteTrieNode(db ethdb.KeyValueWriter, hash common.Hash, node []byte) {
	if err := db.Put(hash.Bytes(), node); err != nil {
		log.Crit("Failed to store trie node", "err", err)
	}
}

// DeleteTrieNode deletes the specified trie node from the database.
func DeleteTrieNode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(hash.Bytes()); err != nil {
		log.Crit("Failed to delete trie node", "err", err)
	}
}

// HasCode reports whether the contract code corresponding to the given hash
// exists in the database under either scheme.
func HasCode(db ethdb.KeyValueReader, hash common.Hash) bool {
	if ok, _ := db.Has(hash[:]); ok {
		return true
	}
	ok, _ := db.Has(codeKey(hash))
	return ok
}

// HasCodeWithPrefix reports whether the contract code exists only under the
// namespaced scheme.
func HasCodeWithPrefix(db ethdb.KeyValueReader, hash common.Hash) bool {
	ok, _ := db.Has(codeKey(hash))
	return ok
}

// HasTrieNode reports whether a trie node with the given hash is present.
func HasTrieNode(db ethdb.KeyValueReader, hash common.Hash) bool {
	ok, _ := db.Has(hash.Bytes())
	return ok
}
