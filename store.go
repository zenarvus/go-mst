package mst

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	cmpck "github.com/zenarvus/compack/go"
	polysha "github.com/zenarvus/polyformats/polysha/go"
)

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
	data, err := cmpck.Marshal(node, cmpck.EncOpts{})
	if err != nil { return NodeHash{}, err }

	hash, err := polysha.HashRaw(m.hashAlgorithm, data)
	if err != nil { return NodeHash{}, err }

	m.db[string(hash)] = node.Clone()
	return hash, nil
}

// ========== SQL STORE ========== //

type SQLInit struct {
	db *sql.DB
	getStmt *sql.Stmt
	putStmt *sql.Stmt
	deleteStmt *sql.Stmt
	table string
}
type SQLStore struct {
	db *sql.DB
	getStmt *sql.Stmt
	putStmt *sql.Stmt
	deleteStmt *sql.Stmt
	table *string

	hashAlgorithm polysha.SHAType
}
// InitSQL creates a table prepares sql statements to use with MST.
func InitSQL(db *sql.DB, tableName string) (*SQLInit, error) {
	// Ensure the table exists
	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (hash BLOB PRIMARY KEY, data BLOB)", tableName)
	if _, err := db.Exec(query); err != nil { return nil, err }

	// Prepare statements
	getStmt, _ := db.Prepare(fmt.Sprintf("SELECT data FROM %s WHERE hash = ?", tableName))
	putStmt, _ := db.Prepare(fmt.Sprintf("INSERT OR REPLACE INTO %s (hash, data) VALUES (?, ?)", tableName))
	deleteStmt, _ := db.Prepare(fmt.Sprintf("DELETE FROM %s WHERE hash = ?", tableName))

	return &SQLInit{
		db: db,
		getStmt: getStmt,
		putStmt: putStmt,
		deleteStmt: deleteStmt,
		table:tableName,
	}, nil
}

// Inherit the same db settings and create a BlockStore with given hashAlgorithm.
// This allows us to use different hashes for different users in the same table.
func (s *SQLInit) SQLStore(hashAlgorithm polysha.SHAType) (*SQLStore,error) {

	return &SQLStore{
		db: s.db,
		getStmt: s.getStmt,
		putStmt: s.putStmt,
		deleteStmt: s.deleteStmt,
		table: &s.table,
		hashAlgorithm:hashAlgorithm,
	}, nil
}

func (s *SQLStore) HashAlgorithm() polysha.SHAType {
	return s.hashAlgorithm
}

func (s *SQLStore) Get(nodeHash NodeHash) (*Node, error) {
	var data []byte
	err := s.getStmt.QueryRow(nodeHash).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("node not found: %x", nodeHash)
	}
	if err != nil { return nil, err }

	node := &Node{}
	err = cmpck.Unmarshal(data, node)
	return node, err
}

func (s *SQLStore) Put(node *Node) (NodeHash, error) {
	data, err := cmpck.Marshal(node, cmpck.EncOpts{})
	if err != nil { return nil, err }

	hash, err := polysha.HashRaw(s.hashAlgorithm, data)
	if err != nil { return nil, err }

	_, err = s.putStmt.Exec(hash, data)
	return hash, err
}

func (s *SQLStore) Delete(nodeHash NodeHash) error {
	_, err := s.deleteStmt.Exec(nodeHash)
	return err
}

func (s *SQLInit) Close() {
	s.getStmt.Close()
	s.putStmt.Close()
	s.deleteStmt.Close()
}
