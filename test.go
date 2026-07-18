package main

import (
	"fmt"
	polysha "github.com/zenarvus/polyformats/polysha/go"
)

func main() {
	// Initialize our modular blockstore
	store := NewMemoryStore(polysha.TYPE_BLAKE3_256)

	// Create Tree A and insert elements in alphabetical order
	treeA := NewTree(store)
	_ = treeA.Insert([]byte("apple"), []byte("1"))
	_ = treeA.Insert([]byte("banana"), []byte("2"))
	_ = treeA.Insert([]byte("cherry"), []byte("3"))

	// Create Tree B and insert the same elements in completely reverse order
	treeB := NewTree(store)
	_ = treeB.Insert([]byte("cherry"), []byte("3"))
	_ = treeB.Insert([]byte("banana"), []byte("2"))
	_ = treeB.Insert([]byte("apple"), []byte("1"))

	fmt.Printf("Tree A Root CID: %s\n", treeA.Root())
	fmt.Printf("Tree B Root CID: %s\n", treeB.Root())

	if treeA.Root() == treeB.Root() {
		fmt.Println("Success")

	} else { fmt.Println("Error: Root hashes did not match.") }

	// Retrieve a key
	val, _ := treeA.Get([]byte("banana"))
	fmt.Printf("Retrieved 'banana': %s\n", string(val))

	//proof, _ := treeA.GetProof([]byte("banana"))
	//fmt.Println(proof)
}
