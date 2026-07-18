package mst

import (
	"errors"
	"sync"

	compack "github.com/zenarvus/compack/go"
	polysha "github.com/zenarvus/polyformats/polysha/go"
)

// Compack is used to hash nodes in a canonical form.
var cmpck = compack.NewCompackHandler(&compack.Options{Canonical:true})

// BlockStore defines the modular interface for reading and writing tree nodes.
type BlockStore interface {
	Get(nodeHash NodeHash) (*Node, error) // Retrieve a node from the store
	Delete(nodeHash NodeHash) error // Delete a node with nodeHash from the store
	Put(node *Node) (NodeHash, error) // Put a node to the store and return it's NodeHash
	HashAlgorithm() polysha.SHAType // Hash algorithm used in the tree.
}

// ========== MEMORY STORE ========== //

// MemoryStore is an in-memory, thread-safe implementation of BlockStore.
type MemoryStore struct {
	mu sync.RWMutex
	db map[string]*Node
	hashAlgorithm polysha.SHAType // Hash algorithm used in the entire tree
}

func NewMemoryStore(hashAlgorithm polysha.SHAType) *MemoryStore {
	return &MemoryStore{db: make(map[string]*Node), hashAlgorithm:hashAlgorithm}
}

func (m *MemoryStore) HashAlgorithm() polysha.SHAType {
	return m.hashAlgorithm
}

func (m *MemoryStore) Get(nodeHash NodeHash) (*Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, exists := m.db[string(nodeHash)]
	if !exists { return nil, errors.New("node not found in store") }
	return node.Clone(), nil
}

func (m *MemoryStore) Delete(nodeHash NodeHash) (error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	delete(m.db, string(nodeHash))
	return nil
}

func (m *MemoryStore) Put(node *Node) (NodeHash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Deterministic serialization to compute the node hash
	data, err := cmpck.Marshal(node)
	if err != nil { return NodeHash{}, err }

	hash, err := polysha.HashRaw(m.hashAlgorithm, data)
	if err != nil { return NodeHash{}, err }

	m.db[string(hash)] = node.Clone()
	return hash, nil
}

// ========== SQL STORE ========== //

// This part is work in progress //
