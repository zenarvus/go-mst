package mst

import (
	"bytes"
	"math/bits"
	"sort"
	"github.com/zenarvus/polyformats/polysha/go"
)

type NodeHash []byte // NodeHash represents the canonicalized hash of the node. We use it to get nodes from the store. (Uses compack)
type ID []byte // IDs are stored inside nodes and they are actual user given pointers to the things they want. Like a db object.

// Node represents a single block in the Merkle Search Tree.
type Node struct {
	Level int `cmpck:"1"`
	Entries []ID `cmpck:"2"` // Entries are the pointers to actual object stored.
	Children []NodeHash `cmpck:"3"` // Length is always len(Entries) + 1. Children are sub nodes.
}

// Clone creates a deep copy of a node to preserve immutability.
func (n *Node) Clone() *Node {
	if n == nil { return nil }

	cloned := &Node{
		Level:    n.Level,
		Entries:  make([]ID, len(n.Entries)),
		Children: make([]NodeHash, len(n.Children)),
	}

	copy(cloned.Entries, n.Entries)
	copy(cloned.Children, n.Children)

	return cloned
}

func (n *Node) isEmpty() bool {
	if len(n.Entries) > 0 { return false } // If there are sub entries, node is not empty.

	// There can also be no entries but just one node.

	// If there is a child node with an non-empty nodeHash, node is not empty.
	for _, childNodeHash := range n.Children {
		if len(childNodeHash) > 0 { return false }
	}

	// Else, node is empty.
	return true
}

// determineLevel calculates a deterministic level based on leading bits of a SHA-256 hash.
func determineLevel(key ID, hashAlgorithm polysha.SHAType) (int,error) {
	hash,err := polysha.HashRaw(hashAlgorithm, key) // Hash the key
	if err!=nil{return 0, err}

	leadingZeros := 0
	for _, b := range hash {
		if b == 0 {
			leadingZeros += 8
		} else {
			leadingZeros += bits.LeadingZeros8(b)
			break
		}
	}
	// A divisor of 2 provides a standard fanout of 4 (base-4 skip list equivalent)
	return leadingZeros / 2, nil
}

// Tree represents the Merkle Search Tree wrapper.
type Tree struct {
	store BlockStore
	rootNodeHash NodeHash
}

func NewTree(store BlockStore) *Tree {
	return &Tree{store: store, rootNodeHash: NodeHash{}}
}

// Return the root NodeHash of the tree.
func (t *Tree) Root() NodeHash { return t.rootNodeHash }

// ========== EXISTENCE CHECK ========== //

// Exists searches for a key in the tree and returns true if it exists.
func (t *Tree) Exists(key []byte) (bool, error) {
	return t.exists(t.rootNodeHash, key) // Start from the root.
}
func (t *Tree) exists(nodeHash NodeHash, key ID) (bool, error) {
	if len(nodeHash) == 0 { return false, nil } // If there is no nodeHash, no value can be getted. Return false. This happens when we reach to the bottom of the tree.

	// How this gonna get apple that comes before banana but in a lower level? (assume word length determines the level).
	// - Oh, banana is the first element and is higher than the apple. It's index is 0, so returned idx will be 0. (Key is not equal to banana so we will traverse down)
	// - Apple is in the first child node which also has an idx of 0.
	//
	// What about grape? It's after cherry and in a lower level.
	// - Then, every key in the current node entries will be lower than it. As the sort.Search won't find anything, it will return len(node.Entries), which is equal to the idx of the child node that contains grape. We will traverse down to the node to that node and find it.

	node, err := t.store.Get(nodeHash) // Find the node with given NodeHash in the store.
	if err != nil { return false, err }

	// sort.Search binary searches and returns an index in a given sorted slice.
	idx := sort.Search(len(node.Entries), func(i int)bool{
		// This index is the index of the entry with a key bigger than or similar with the given key.
		return bytes.Compare(node.Entries[i], key) >= 0
		// Meaning, if the key exists, it returns it's index. If it does not exist, it returns the index of the key bigger than given key.
	})

	// If index is within the range of slice, and the key with that index in the entries match with the given key
	if idx < len(node.Entries) && bytes.Equal(node.Entries[idx], key) {
		// We found it. Return the key
		return true, nil
	}

	// Else, search for this key's value in the children with the index we found. Because if the key does not exist in the current node's entries, we need to traverse the tree down.
	// As the entry with key does not exist in the current node entries, idx is the index of the key bigger than the given key.
	// Children nodes store the sub entries with keys that come after the entry with idx in the current node.
	return t.exists(node.Children[idx], key)
}

// ========== KEY INSERTION ========== //

// Insert adds a key in the tree and updates nodes to their new NodeHash until to the root.
func (t *Tree) Insert(key ID) error {
	// We determine the level of the key by counting the leading zeros in it's hash.
	level,err := determineLevel(key, t.store.HashAlgorithm())
	if err!=nil{return err}

	// Then we insert it in the given level. We start from root for looking, and traverse down.
	newRoot, err := t.insert(t.rootNodeHash, key, level)
	if err != nil { return err }

	// We get the new root and update the current one with that.
	t.rootNodeHash = newRoot
	return nil
}
func (t *Tree) insert(nodeHash NodeHash, key ID, keyLevel int) (NodeHash, error) {
	// If node with this NodeHash does not exist, we create one and assign it the keyLevel.
	// We put our key/value there and create two empty child nodes.
	if len(nodeHash) == 0 {
		newNode := &Node{
			Level:    keyLevel,
			Entries:  []ID{key},
			Children: []NodeHash{{}, {}},
		}
		return t.store.Put(newNode) // Calculate node's canonical hash and put to the store with that NodeHash. Then, return that NodeHash.
		// We use returned NodeHash to update the parent node's previously empty children NodeHash. (The one had nodeHash). The logic of it is below.
		// Or if the tree was empty, (thus t.root was empty) nodeHash will be empty and this node will be the parent node. And it's becomes the root NodeHash.
	}

	// If nodeHash is not empty, we get it from the store.
	node, err := t.store.Get(nodeHash)
	if err != nil { return []byte{}, err }

	// If the key we wanna insert has a higher level than the node we get, it must be in a newNode that is parent of node with nodeHash.
	// We use t.split function for that. It splits nodeHash and it's entire subtree in half.
	if keyLevel > node.Level {
		leftSubtree, rightSubtree, err := t.split(nodeHash, key) // If rightSubtree is empty, leftSubtree will be equal to nodeHash. Same is true vice versa.
		if err != nil { return []byte{}, err }

		// Then create a new parent node with our higher keyLevel and insert our key in there.
		// leftSubtree contains the keys lexically comes before our key.
		// rightSubtree contains the keys lexically comes after our key.
		newNode := &Node{
			Level:    keyLevel,
			Entries:  []ID{key},
			Children: []NodeHash{leftSubtree, rightSubtree},
		}

		// Only delete the original nodeHash if it was NOT reused by one of the splits
		if len(nodeHash) > 0 && !bytes.Equal(nodeHash, leftSubtree) && !bytes.Equal(nodeHash, rightSubtree) {
			err = t.store.Delete(nodeHash)
			if err != nil { return NodeHash{}, err }
		}

		return t.store.Put(newNode) // Then we insert our new node and return it's NodeHash.
	}

	// If the new key has the same level with the node we found (one with nodeHash), we need to insert it in there.
	if keyLevel == node.Level {
		// Find the index of an entry in the node. An entry with a key that is higher or equal to our key.
		idx := sort.Search(len(node.Entries), func(i int) bool {
			return bytes.Compare(node.Entries[i], key) >= 0
		})

		// If entry/key already exists, we simply return the nodeHash of the node.
		if idx < len(node.Entries) && bytes.Equal(node.Entries[idx], key) {
			return nodeHash, nil
		}

		// If the new entry does not exist in the current node, we use the logic below.

		// We split the child node at idx using our new key.
		// idx is the index of the entry with a key lexically higher than our key.
		// This idx also the node that contains sub entries that with lexically lower and higher keys than our new entry's key. (but this node's entries are lexically before than the node currently at idx)
		// So we need to split that node.
		leftSubtree, rightSubtree, err := t.split(node.Children[idx], key)
		if err != nil { return NodeHash{}, err }

		newNode := node.Clone() // Clone the nodeHash node.

		// We need to place our new key to the idx and shift everything after that to the right.
		// Because it's key is lexically higher than the entry in idx-1 but lexically lower than the entry at idx.
		newNode.Entries = append(newNode.Entries, ID{}) // Append a new entry to the node.
		copy(newNode.Entries[idx+1:], newNode.Entries[idx:]) // Copy everything from idx to the end to idx+1 to the end. Which shifts everything to right and empties the entry at idx. (First argument is the destination and the second is the source. Not vice versa)
		newNode.Entries[idx] = key // Then we insert our new entry to idx.

		// We also need to shift the sub nodes to one right and insert our new sub node where it belongs.

		newNode.Children[idx] = leftSubtree // leftSubtree should be at idx. It contains the things lexically before than our new key.
		newNode.Children = append(newNode.Children, NodeHash{}) // Append an empty space to the children.
		copy(newNode.Children[idx+2:], newNode.Children[idx+1:]) // Shift everything starting from idx+1 to one right. Make space for rightSubtree.
		newNode.Children[idx+1] = rightSubtree // Insert the rightSubtree. It contains sub entries with lexically higher keys than our new key (currently at idx), but lexically lower keys than the entry that was previously at idx but now at idx+1.

		err = t.store.Delete(nodeHash) // newNode will have a different hash and nodeHash is not needed anymore. We delete it.
		if err != nil {return NodeHash{}, err}

		return t.store.Put(newNode) // Put our new node to the store and return it's new NodeHash. The parent node will update the child to the new NodeHash using the returned value.
	}

	// If the new key we wanna insert has a lower level, we need to recurse down and insert it at lower levels.
	// And update new node hashes until to the top.

	// We get the index of the entry with a key lexically higher than our new key.
	idx := sort.Search(len(node.Entries), func(i int) bool {
		return bytes.Compare(node.Entries[i], key) >= 0
	})

	// This idx also responds to the node that holds sub entries with our key's lexical range. We need to insert it there.
	newChildNodeHash, err := t.insert(node.Children[idx], key, keyLevel)
	if err != nil { return NodeHash{}, err }

	// After the insertion, we get the new calculated nodeHash of the node at node.Children[idx]

	newNode := node.Clone() // Clone the node and its entries and children nodeHash addresses.
	newNode.Children[idx] = newChildNodeHash // Update the child node's nodeHash with the new nodeHash address.

	err = t.store.Delete(nodeHash) // We do not need nodeHash node anymore. New node has a different hash. We delete the old one.
	if err != nil {return NodeHash{}, err}

	return t.store.Put(newNode) // Put our new node to the store and return it's NodeHash.
	// At the end of recursion, this is the root node's hash.
}

// split divides a subtree into two subtrees around a split key.
func (t *Tree) split(nodeHash NodeHash, key ID) (NodeHash, NodeHash, error) {
	if len(nodeHash) == 0 { return NodeHash{}, NodeHash{}, nil } // If nodeHash is empty, we return two empty subtrees.

	node, err := t.store.Get(nodeHash) // Get the node with given ID.
	if err != nil { return NodeHash{}, NodeHash{}, err }

	// Look for a node index higher than or equal to our key. This index and things after that should be at the right tree.
	// Others should be at the left tree. Left tree is for entries with lexically lower keys than the key passed as an argument.
	idx := sort.Search(len(node.Entries), func(i int) bool {
		return bytes.Compare(node.Entries[i], key) >= 0
	})

	// Create two new nodes with our old node's level.
	leftNode := &Node{Level: node.Level}
	rightNode := &Node{Level: node.Level}

	// Insert the entries and children until idx to the left node.
	leftNode.Entries = append([]ID(nil), node.Entries[:idx]...)
	leftNode.Children = append([]NodeHash(nil), node.Children[:idx]...)

	// Insert the entries from idx to the end to the right node.
	rightNode.Entries = append([]ID(nil), node.Entries[idx:]...)

	// Insert children nodes from idx+1 to the end to the right node.
	rightNode.Children = append([]NodeHash(nil), node.Children[idx+1:]...)

	// The logic for the node at the idx is different.
	// This node was holding entries with keys higher than left node's last entry but lower than right node's first entry.
	// Meaning, it contains things in left and right of our key. So we need to split it into two parts too.
	// This process is recursive, because it's also true for lower level nodes. Left and right parts are sharing one common middle node which needs to be splitted to lexically lower and higher parts until the end.
	boundaryChild := node.Children[idx]
	leftSubChild, rightSubChild, err := t.split(boundaryChild, key) // This saves left and right subchild to the store and returns their NodeHash.
	if err != nil { return NodeHash{}, NodeHash{}, err }

	// Add leftSubChild to the leftNode's children. (to the end)
	leftNode.Children = append(leftNode.Children, leftSubChild)
	// Add rightSubChild to the rightNode's children. (to the start)
	rightNode.Children = append([]NodeHash{rightSubChild}, rightNode.Children...)

	// Insert left and right nodes to the store and get their nodeHash addresses.
	var leftNodeHash, rightNodeHash NodeHash
	if !leftNode.isEmpty() {
		leftNodeHash, err = t.store.Put(leftNode)
		if err != nil { return NodeHash{}, NodeHash{}, err }
	}
	if !rightNode.isEmpty() {
		rightNodeHash, err = t.store.Put(rightNode)
		if err != nil { return NodeHash{}, NodeHash{}, err }
	}

	// Finally, return those nodes' nodeHash addresses.
	return leftNodeHash, rightNodeHash, nil
}

// ========== KEY DELETION ========== //

// Delete() deletes a key/id/entry from the tree by applying a reverse logic of insertion.
func (t *Tree) Delete(key ID) error {
	// Call the actual recursive function and get the resulting new root hash
	newRoot, err := t.delete(t.rootNodeHash, key)
	if err != nil {return err}

	t.rootNodeHash = newRoot // Update the tree's root with the new hash.
	return nil
}
func (t *Tree) delete(nHash NodeHash, key ID) (NodeHash, error) {
	if len(nHash) == 0 {return nil, nil} // When nHash becomes empty, it means we reached to the bottom.

	// Get the node with nHash
	node, err := t.store.Get(nHash)
	if err!=nil  {return nil, err}

	// Get the index of the key in the current node's entries
	// or if it does not exists, get the index of the next element with lexically higher key.
	// if there is no lexically higher key, return the length of the entries slice. Which is the same with the last child node's index.
	idx := sort.Search(len(node.Entries), func(i int) bool {
		return bytes.Compare(node.Entries[i], key) >= 0
	})

	newNode := node.Clone() // Deep copy node to newNode. We will modify it.

	// Analyze the blocks inside if/else, and you are good to go! Write the test files and sql adapter, and boom!

	// If the key is found in the current node
	if idx < len(node.Entries) && bytes.Equal(node.Entries[idx], key) {

		// As we delete this key, we need to merge the two child subtrees separated by this key.
		mergedChild, err := t.merge(newNode.Children[idx], newNode.Children[idx+1])
		if err != nil { return nil, err }

		// After that, we remove the key from entries.
		newNode.Entries = append(newNode.Entries[:idx], newNode.Entries[idx+1:]...)

		// And we replace the two child nodes (left and right of key) with the merged child.
		newNode.Children = append(newNode.Children[:idx], newNode.Children[idx+1:]...)
		newNode.Children[idx] = mergedChild

		// If this node becomes empty as a result of deletion, it should be ignored and we should return the child of it instead of this node.
		if len(newNode.Entries) == 0 {
			err = t.store.Delete(nHash)
			if err != nil { return nil, err }
			return mergedChild, nil
		}

	// IF the key is not in this node, recurse down to the correct child.
	} else {

		// If the key is not in this node, recurse down to the child node with the same boundary.
		newChildHash, err := t.delete(newNode.Children[idx], key)
		if err != nil { return nil, err }

		// If nothing changed down the line, return the existing hash
		if bytes.Equal(newNode.Children[idx], newChildHash) {
			return nHash, nil
		}

		// If a change happened, update the changed child with it's new hash.
		newNode.Children[idx] = newChildHash
	}

	// At the end, the node's contents have changed. Delete the old node and store the new one with a new NodeHash.

	err = t.store.Delete(nHash) // Delete
	if err != nil { return nil, err }

	return t.store.Put(newNode) // Return the new NodeHash. At the end of recursion, this will be the new root.
}

// merge recombines two subtrees into a single subtree
// This is the direct inverse logic of the split operation
func (t *Tree) merge(leftHash, rightHash NodeHash) (NodeHash, error) {

	// If leftHash is empty, the right part should be the new subtree. It's the end of recursion.
	if len(leftHash) == 0 { return rightHash, nil }
	// If rightHash is empty, the left part should be the new subtree. It's the end of recursion.
	if len(rightHash) == 0 { return leftHash, nil }

	// Get the left and right nodes.
	leftNode, err := t.store.Get(leftHash)
	if err != nil { return nil, err }
	rightNode, err := t.store.Get(rightHash)
	if err != nil { return nil, err }

	// newNode will be the final result of the merge operation. We will save it to the store and return it's NodeHash
	var newNode *Node

	// If the left node has a higher level, it should become the parent.
	// We merge the right node into the right-most child of the left node.
	if leftNode.Level > rightNode.Level {
		newNode = leftNode.Clone() // Deep copy the leftNode
		lastIdx := len(newNode.Children) - 1 // Get the index of leftNode's right-most child.

		// Recursively merge the right-most child with the rightHash node and return the resulting merged NodeHash
		mergedChild, err := t.merge(newNode.Children[lastIdx], rightHash)
		if err != nil { return nil, err }

		newNode.Children[lastIdx] = mergedChild // Update the last node with the new hash

		err = t.store.Delete(leftHash); // leftNode is now unnecessary. Delete it from the store.
		if err != nil { return nil, err }
	
	// If the right node has a higher level, it should become the parent.
	// We merge the left node into the left-most child of the right node.
	} else if leftNode.Level < rightNode.Level {
		newNode = rightNode.Clone()

		// Recursively merge the first child with the leftHash node and return the resulting merged NodeHash.
		// As the leftHash's entries will have lexically lower IDs than right node's first child, it should be at the left.
		mergedChild, err := t.merge(leftHash, newNode.Children[0])
		if err != nil { return nil, err }

		newNode.Children[0] = mergedChild // Update the first node with the new hash

		err = t.store.Delete(rightHash); // rightNode is now unnecessary. Delete it from the store.
		if err != nil { return nil, err }

	// If both nodes are at the same level, we combine them.
	// All entries in the left node are always lexically lower than the right node.
	} else {

		newNode = &Node{Level: leftNode.Level}

		// Combine entries in the node. It's the easiest part.
		newNode.Entries = make([]ID, 0, len(leftNode.Entries)+len(rightNode.Entries)) // Allocate once
		newNode.Entries = append(newNode.Entries, leftNode.Entries...)
		newNode.Entries = append(newNode.Entries, rightNode.Entries...)

		// The boundary is the right-most child of the left node and the left-most child of the right node.
		// These two sub-children share the same lexical boundary space and must be merged.

		lastLeftChild := leftNode.Children[len(leftNode.Children)-1] // Get the last child of left node.
		firstRightChild := rightNode.Children[0] // Get the first child of the right node
		mergedBoundary, err := t.merge(lastLeftChild, firstRightChild) // Recursively merge them.
		if err != nil { return nil, err }

		// Now we combine child nodes inside newNode in this order: Left's children except last, merged boundary, right's children except first
		// In [a:b] where a and b are indexes of the elements, a is included and b is excluded.
		newNode.Children = make([]NodeHash, 0, len(leftNode.Children)+len(rightNode.Children)-1) // Allocate once.
		newNode.Children = append(newNode.Children, leftNode.Children[:len(leftNode.Children)-1]...)
		newNode.Children = append(newNode.Children, mergedBoundary)
		newNode.Children = append(newNode.Children, rightNode.Children[1:]...)

		// Remove the left and right nodes. They are unnecessary now.
		err = t.store.Delete(leftHash)
		if err != nil { return nil, err }
		err = t.store.Delete(rightHash)
		if err != nil { return nil, err }
	}

	return t.store.Put(newNode) // Finally, put the generated new node to the store and return it's NodeHash.
}
