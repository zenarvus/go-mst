package main

import (
	"encoding/hex"
	"errors"
	"sync"

	polysha "github.com/zenarvus/polyformats/polysha/go"
)

// BlockStore defines the modular interface for reading and writing tree nodes.
type BlockStore interface {
	Get(cid CID) (*Node, error) // Retrieve a node from the store
	Put(node *Node) (CID, error) // Put a node to the store
	HashAlgorithm() polysha.SHAType // Hash algorithm used in the tree.
}

// MemoryStore is an in-memory, thread-safe implementation of BlockStore.
type MemoryStore struct {
	mu sync.RWMutex
	db map[CID]*Node
	hashAlgorithm polysha.SHAType // Hash algorithm used in the entire tree
}

func NewMemoryStore(hashAlgorithm polysha.SHAType) *MemoryStore {
	return &MemoryStore{db: make(map[CID]*Node), hashAlgorithm:hashAlgorithm}
}

func (m *MemoryStore) HashAlgorithm() polysha.SHAType {
	return m.hashAlgorithm
}

func (m *MemoryStore) Get(cid CID) (*Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, exists := m.db[cid]
	if !exists { return nil, errors.New("node not found in store") }
	return node.Clone(), nil
}

func (m *MemoryStore) Put(node *Node) (CID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Deterministic serialization to compute the content hash (CID)
	data, err := cmpck.Marshal(node)
	if err != nil { return "", err }

	hash, err := polysha.HashRaw(m.hashAlgorithm, data)
	if err != nil { return "", err }

	cid := CID(hex.EncodeToString(hash[:]))

	m.db[cid] = node.Clone()
	return cid, nil
}
