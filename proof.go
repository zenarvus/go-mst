package mst

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	cmpck "github.com/zenarvus/compack/go"
	polysha "github.com/zenarvus/polyformats/polysha/go"
)

// GetProof generates a path proof for a given key. The first node in the slice is root and the level decreases to the left.
func (t *Tree) GetProofPath(tid []byte) ([]Node, error) {
	var path []Node
	currNodeHash := t.rootNodeHash

	// Run until currNodeHash is empty.
	for len(currNodeHash) > 0 {
		node, err := t.store.Get(currNodeHash) // Get the node with currNodeHash address.
		if err != nil { return nil, fmt.Errorf("failed to retrieve node during proof generation: %w", err) }
		
		// Append a clone of the node to the proof path
		path = append(path, *node)

		numEntries := len(node.Entries)/2
		// Search for the key in the current node.
		idx := sort.Search(numEntries, func(i int) bool {
			return bytes.Compare(node.TID(i), tid) >= 0
		})

		// If we found the key, the path is complete. Return it
		if idx < numEntries && bytes.Equal(node.TID(idx), tid) { return path, nil }

		// Otherwise, move to the child pointing to where the key should be.
		currNodeHash = node.Children[idx]
	}

	return nil, errors.New("key not found in the tree and cannot generate membership proof")
}

// Verify checks if the proof is valid for a given tid and cid, expected hash, and hash algorithm. It returns nil if the proof is valid.
func VerifyProofPath(proofPath []Node, tid, cid []byte, expectedRootHash []byte, hashAlgorithm polysha.SHAType) error {
	if len(proofPath) == 0 { return errors.New("proof path is empty") }

	expectedNodeHash := expectedRootHash

	for i, node := range proofPath {
		// Canonicalize the node to verify its NodeHash matches the expected NodeHash
		data, err := cmpck.Marshal(&node, cmpck.EncOpts{Canonical:true})
		if err != nil { return fmt.Errorf("failed to serialize node: %w", err) }
		// Calculate the node's hash. If it's the first item in the slice, it should be the root and it's hash should match with the hash passed to the function.
		hash, err := polysha.HashRaw(hashAlgorithm, data)
		if err != nil { return err }

		if !bytes.Equal(hash, expectedNodeHash) { return fmt.Errorf("cryptographic link broken at path index %d", i) }

		numEntries := len(node.Entries)/2
		// Binary search the node's entries for our target key
		idx := sort.Search(numEntries, func(j int) bool {
			return bytes.Compare(node.TID(j), tid) >= 0
		})

		// If this is the node containing the key, then traversal and verification is successful.
		if idx < numEntries && bytes.Equal(node.TID(idx), tid) {
			// Still, we should check if any leftover paths remaining. The proof should only contain the path needed to verify our key.
			if i != len(proofPath)-1 {
				return fmt.Errorf("spare proof path items left")
			}
			
			if len(node.Entries) < 2*idx+1 { return errors.New("invalid entry length") }

			if !bytes.Equal(node.Entries[2*idx+1], cid) {
				return errors.New("CID does not match with the claimed one")
			}

			return nil // The proof is valid, error is nil
		}

		// Otherwise, set the expected NodeHash to the next child node's hash which contains the boundary our key is in.
		if idx >= len(node.Children) { return errors.New("proof path index out of bounds") }
		expectedNodeHash = node.Children[idx]
	}

	return errors.New("key was not found in the provided proof path")
}
