package mst

import (
	"bytes"
	"testing"

	polysha "github.com/zenarvus/polyformats/polysha/go"
)

func TestMSTUsage(t *testing.T) {
	hashAlgo := polysha.TYPE_BLAKE3_256

	// Initialize stores for our different tree states
	storeA := NewMemoryStore(hashAlgo)
	storeB := NewMemoryStore(hashAlgo)
	storeC := NewMemoryStore(hashAlgo)

	treeA := GetTree(storeA, nil)
	treeB := GetTree(storeB, nil)
	treeC := GetTree(storeC, nil)

	keys := [][]byte{
		[]byte("apple"), []byte("banana"), []byte("berry"),
		[]byte("cherry"), []byte("grape"), []byte("melon"),
		[]byte("pear"), []byte("plums"),
	}

	// Insertion and determinism

	// Insert into Tree A in alphabetical order
	for _, key := range keys {
		cid,err := polysha.Hash(hashAlgo, key)
		if err != nil {t.Fatalf("Failed to calculate the hash for '%s': %v",key, err)}
		if err := treeA.Insert(key, cid); err != nil {
			t.Fatalf("Failed to insert '%s' into Tree A: %v", key, err)
		}
	}
	// Insert into Tree B in reverse alphabetical order
	for i := len(keys) - 1; i >= 0; i-- {
		cid,err := polysha.Hash(hashAlgo, keys[i])
		if err != nil {t.Fatalf("Failed to calculate the hash for '%s': %v",keys[i], err)}
		if err := treeB.Insert(keys[i], cid); err != nil {
			t.Fatalf("Failed to insert '%s' into Tree B: %v", keys[i], err)
		}
	}

	// A Merkle Search Tree must yield the exact same root hash regardless of insertion order
	if !bytes.Equal(treeA.Root(), treeB.Root()) {
		t.Fatalf("Determinism failure: Tree A root (%x) != Tree B root (%x)", treeA.Root(), treeB.Root())
	}

	// Existence checks (positive)
	for _, key := range keys {
		exists, err := treeA.Exists(key)
		if err != nil { t.Errorf("Error checking existence for '%s': %v", key, err) }

		if !exists { t.Errorf("Expected key '%s' to exist in the tree, but it does not", key) }
	}

	// Existence checks (negative)
	missingKey := []byte("strawberry")
	exists, err := treeA.Exists(missingKey)
	if err != nil { t.Errorf("Error checking existence for missing key: %v", err) }
	if exists { t.Errorf("Expected key '%s' to NOT exist, but it falsely returned true", missingKey) }

	targetKey := []byte("banana")
	targetCid,err := polysha.Hash(hashAlgo, targetKey)
	if err != nil {t.Fatalf("Failed to calculate the hash for '%s': %v", targetKey, err)}

	// Proof generation and verification (positive)
	proofPath, err := treeA.GetProofPath(targetKey)
	if err != nil { t.Fatalf("Failed to get proof path for '%s': %v", targetKey, err) }

	err = VerifyProofPath(proofPath, targetKey, targetCid, treeA.Root(), hashAlgo)
	if err != nil { t.Errorf("Failed to verify valid proof for '%s': %v", targetKey, err) }

	// Proof verification (negative)
	// Try to verify the valid 'banana' proof against a different key with a different proof path ('plums')
	err = VerifyProofPath(proofPath, []byte("plums"), []byte("12345"), treeA.Root(), hashAlgo)
	if err == nil { t.Errorf("Expected proof verification to fail for mismatched key, but it falsely succeeded") }

	// Deletion and determinism
	// Insert everything except "banana" into Tree C
	for _, key := range keys {
		if !bytes.Equal(key, targetKey) {
			cid,err := polysha.Hash(hashAlgo, key)
			if err != nil {t.Fatalf("Failed to calculate the hash for '%s': %v",key, err)}
			if err := treeC.Insert(key, cid); err != nil {
				t.Fatalf("Failed to insert '%s' into Tree C: %v", key, err)
			}
		}
	}

	// Delete "banana" from Tree A
	if err := treeA.Delete(targetKey); err != nil { t.Fatalf("Failed to delete '%s' from Tree A: %v", targetKey, err) }

	// Ensure the key is actually gone
	exists, _ = treeA.Exists(targetKey)
	if exists { t.Errorf("Key '%s' still exists in Tree A after deletion", targetKey) }

	// The root of Tree A (which had "banana" inserted then deleted) should now exactly match Tree C (which never had "banana" inserted to begin with).
	if !bytes.Equal(treeA.Root(), treeC.Root()) {
		t.Errorf("Deletion determinism failure: Tree A root (%x) != Tree C root (%x)", treeA.Root(), treeC.Root())
	}
}
