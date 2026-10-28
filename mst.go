package mst

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"sort"

	"github.com/zenarvus/polyformats/polysha/go"
)

type NodeHash []byte // NodeHash represents the canonicalized hash of the node. We use it to get nodes from the store. (Uses compack)

// Node represents a single block in the Merkle Search Tree.
type Node struct {
	Level int `cmpck:"1"`
	Entries [][]byte `cmpck:"2"` // Entries are TID/CID value pairs. Index 2*i is fcTID, index 2*i + 1 is CID. TID used for sorting while CID is used to determine the level.
	Children []NodeHash `cmpck:"3"` // Length is always len(Entries)/2 + 1. Children are sub nodes.
}
// TID reconstructs the full uncompressed TID for entry at index i using front coding.
func (n *Node) TID(i int) []byte {
	if i < 0 {return nil}
	var tid []byte
	var prev []byte
	for j := 0; j <= i; j++ {
		fcTID := n.Entries[2*j]
		decoded,err := frontDecode(prev, fcTID)
		if err != nil { return nil }

		tid = append([]byte(nil), decoded...)
		prev = tid
	}
	return tid
}

// extractEntries decodes all front-coded entries into a flat uncompressed [tid0, cid0, tid1, cid1, ...] list.
func extractEntries(nodeEntries [][]byte) [][]byte {
	num := len(nodeEntries) / 2
	res := make([][]byte, 2*num)
	var prev []byte
	for i := 0; i < num; i++ {
		fcTID := nodeEntries[2*i]
		cid := nodeEntries[2*i+1]
		tid, _ := frontDecode(prev, fcTID)

		// Deep copy to ensure complete isolation
		res[2*i] = append([]byte(nil), tid...)
		res[2*i+1] = append([]byte(nil), cid...)
		prev = res[2*i]
	}
	return res
}
// compressFlatEntries compresses a flat uncompressed [tid0, cid0, tid1, cid1, ...] list into front-coded [fcTid0, cid0, fcTid1, cid1, ...].
func compressFlatEntries(flatTidCids [][]byte) [][]byte {
	num := len(flatTidCids) / 2
	compressed := make([][]byte, 2*num)
	var prevTID []byte
	for i := 0; i < num; i++ {
		tid := flatTidCids[2*i]
		cid := flatTidCids[2*i+1]
		fcTID := frontCode(prevTID, tid)

		compressed[2*i] = fcTID
		compressed[2*i+1] = cid
		prevTID = tid
	}
	return compressed
}
// Compress a given TID with front coding relative to the previous uncompressed TID based on the common prefix length
func frontCode(prev []byte, tid []byte) ( compressed []byte ) {
	// We will iterate through one of them. We choose the one with less characters.
	n := len(prev)
	if len(tid) < n {n = len(tid)}

	// get the common byte prefix length
	i := 0
	for i < n && prev[i] == tid[i] { i++ }

	// format: [varint prefix-length][remaining str suffix]
	compressed = make([]byte, 0, binary.MaxVarintLen64+len(tid)-1) // create a byte buffer capable of holding everything
	compressed = binary.AppendUvarint(compressed, uint64(i)) // Write the prefix length matched
	compressed = append(compressed, tid[i:]...) // Append the rest of the string to the compressed form.

	return compressed
}
// Decompress a given front coded TID using the previous uncompressed TID
func frontDecode(prev []byte, compressed []byte) (tid []byte, err error) {
	prefixLen, n := binary.Uvarint(compressed)
	if n <= 0 { return nil, errors.New("invalid or corrupted varint encoding") }
	if len(prev) < int(prefixLen) { return nil, errors.New("prefix length exceeds previous string length")}

	// Allocate a completely fresh slice with its own backing array
    tid = make([]byte, int(prefixLen) + len(compressed) - n)
    copy(tid, prev[:prefixLen])
    copy(tid[prefixLen:], compressed[n:])

	return tid, nil
}

// Clone creates a deep copy of a node to preserve immutability.
func (n *Node) Clone() *Node {
	if n == nil { return nil }

	cloned := &Node{
		Level:    n.Level,
		Entries:  make([][]byte, len(n.Entries)),
		Children: make([]NodeHash, len(n.Children)),
	}

	for i, entry := range n.Entries {
        if entry != nil {
            cloned.Entries[i] = append([]byte(nil), entry...)
        }
    }

    for i, child := range n.Children {
        if child != nil {
            cloned.Children[i] = append([]byte(nil), child...)
        }
    }

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

// determineLevel calculates a deterministic level by counting the leading zeros in the hash
func determineLevel(cid polysha.PolySHA) (int,error) {

	// We should exclude the hash type
	_,hash, err := polysha.SeparatePolySHA(cid)
	if err != nil {return 0,err}

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

// GetTree returns a *Tree struct living inside store with the given root node.
// root can be nil/empty if there is no pre-existing tree yet. A tree will be automatically created upon insertion.
func GetTree(store BlockStore, root NodeHash) *Tree {
	if root == nil {root = NodeHash{}}
	return &Tree{store: store, rootNodeHash: root}
}

// Return the root NodeHash of the tree.
func (t *Tree) Root() NodeHash { return t.rootNodeHash }

// ========== EXISTENCE CHECK ========== //

// Exists searches for a TID in the tree and returns true if it exists.
func (t *Tree) Exists(tid []byte) (bool, error) {
	return t.exists(t.rootNodeHash, tid) // Start from the root.
}
func (t *Tree) exists(nodeHash NodeHash, tid []byte) (bool, error) {
	if len(nodeHash) == 0 { return false, nil } // If there is no nodeHash, no value can be getted. Return false. This happens when we reach to the bottom of the tree.

	// How this gonna get apple that comes before banana but in a lower level? (assume word length determines the level).
	// - Oh, banana is the first element and is higher than the apple. It's index is 0, so returned idx will be 0. (Key is not equal to banana so we will traverse down)
	// - Apple is in the first child node which also has an idx of 0.
	//
	// What about grape? It's after cherry and in a lower level.
	// - Then, every key in the current node entries will be lower than it. As the sort.Search won't find anything, it will return len(node.Entries), which is equal to the idx of the child node that contains grape. We will traverse down to the node to that node and find it.

	node, err := t.store.Get(nodeHash) // Find the node with given NodeHash in the store.
	if err != nil { return false, err }

	numEntries := len(node.Entries)/2
	// sort.Search binary searches and returns an index in a given sorted slice.
	idx := sort.Search(numEntries, func(i int)bool{
		// This index is the index of the entry with a tid bigger than or similar with the given key.
		return bytes.Compare(node.TID(i), tid) >= 0
		// Meaning, if the key exists, it returns it's index. If it does not exist, it returns the index of the key bigger than given key.
	})

	// If index is within the range of slice, and the key with that index in the entries match with the given key
	if idx < numEntries && bytes.Equal(node.TID(idx), tid) {
		// We found it. Return the key
		return true, nil
	}

	// Else, search for this key's value in the children with the index we found. Because if the key does not exist in the current node's entries, we need to traverse the tree down.
	// As the entry with key does not exist in the current node entries, idx is the index of the key bigger than the given key.
	// Children nodes store the sub entries with keys that come after the entry with idx in the current node.
	return t.exists(node.Children[idx], tid)
}

// ========== ENTRY INSERTION ========== //

// Insert adds an entry in the tree and updates nodes to their new NodeHash until to the root.
func (t *Tree) Insert(tid []byte, cid polysha.PolySHA) error {
	// We determine the level of the key by counting the leading zeros in it's hash.
	level,err := determineLevel(cid)
	if err!=nil{return err}

	// Then we insert it in the given level. We start from root for looking, and traverse down.
	newRoot, err := t.insert(t.rootNodeHash, tid, cid, level)
	if err != nil { return err }

	// We get the new root and update the current one with that.
	t.rootNodeHash = newRoot
	return nil
}
func (t *Tree) insert(nodeHash NodeHash, tid, cid []byte, entryLevel int) (NodeHash, error) {
	// If node with this NodeHash does not exist, we create one and assign it the keyLevel.
	// We put our tid/cid there and create two empty child nodes.
	if len(nodeHash) == 0 {
		newNode := &Node{
			Level:    entryLevel,
			Entries:  compressFlatEntries([][]byte{tid, cid}),
			Children: []NodeHash{{}, {}},
		}
		return t.store.Put(newNode) // Calculate node's canonical hash and put to the store with that NodeHash. Then, return that NodeHash.
		// We use returned NodeHash to update the parent node's previously empty children NodeHash. (The one had nodeHash). The logic of it is below.
		// Or if the tree was empty, (thus t.root was empty) nodeHash will be empty and this node will be the parent node. And it's becomes the root NodeHash.
	}

	// If nodeHash is not empty, we get it from the store.
	node, err := t.store.Get(nodeHash)
	if err != nil { return []byte{}, err }

	// If the TID we wanna insert has a higher level than the node we get, it must be in a newNode that is parent of node with nodeHash.
	// We use t.split function for that. It splits nodeHash and it's entire subtree in half.
	if entryLevel > node.Level {
		leftSubtree, rightSubtree, err := t.split(nodeHash, tid) // If rightSubtree is empty, leftSubtree will be equal to nodeHash. Same is true vice versa.
		if err != nil { return []byte{}, err }

		// Then create a new parent node with our higher keyLevel and insert our entry in there.
		// leftSubtree contains the keys lexically comes before our key.
		// rightSubtree contains the keys lexically comes after our key.
		newNode := &Node{
			Level:    entryLevel,
			Entries:  compressFlatEntries([][]byte{tid, cid}),
			Children: []NodeHash{leftSubtree, rightSubtree},
		}

		// Only delete the original nodeHash if it was NOT reused by one of the splits
		if len(nodeHash) > 0 && !bytes.Equal(nodeHash, leftSubtree) && !bytes.Equal(nodeHash, rightSubtree) {
			err = t.store.Delete(nodeHash)
			if err != nil { return NodeHash{}, err }
		}

		return t.store.Put(newNode) // Then we insert our new node and return it's NodeHash.
	}

	// If the new entry TID has the same level with the node we found (one with nodeHash), we need to insert it in there.
	if entryLevel == node.Level {
		numEntries := len(node.Entries)/2
		// Find the index of an entry in the node. An entry with a TID that is higher or equal to our TID.
		idx := sort.Search(numEntries, func(i int) bool {
			return bytes.Compare(node.TID(i), tid) >= 0
		})

		// If entry already exists in this level, update it's CID
		if idx < numEntries && bytes.Equal(node.TID(idx), tid) {
			flat := extractEntries(node.Entries)
			flat[2*idx+1] = append([]byte(nil), cid...)

			newNode := &Node{
				Level:    node.Level,
				Entries:  compressFlatEntries(flat),
				Children: append([]NodeHash(nil), node.Children...),
			}

			err = t.store.Delete(nodeHash)
			if err != nil { return NodeHash{}, err }

			return t.store.Put(newNode)
		}

		// If the new entry does not exist in the current node, we use the logic below.

		// We split the child node at idx using our new TID.
		// idx is the index of the entry with a TID lexically higher than our TID.
		// This idx also the node that contains sub entries that with lexically lower and higher TIDs than our new entry's TID. (but this node's entries are lexically before than the node currently at idx)
		// So we need to split that node.
		leftSubtree, rightSubtree, err := t.split(node.Children[idx], tid)
		if err != nil { return NodeHash{}, err }

		newNode := node.Clone() // Clone the nodeHash node.
		flat := extractEntries(newNode.Entries)

		// We need to place our new entry to the idx and shift everything after that to the right.
		// Because it's TID is lexically higher than the entry in idx-1 but lexically lower than the entry at idx.
		newFlat := make([][]byte, len(flat)+2)
		copy(newFlat, flat[:2*idx])
		newFlat[2*idx] = tid; newFlat[2*idx+1] = cid // add the new entry to the node
		copy(newFlat[2*idx+2:], flat[2*idx:]) // shift everything at the right

		newNode.Entries = compressFlatEntries(newFlat)

		// We also need to shift the sub nodes to one right and insert our new sub node where it belongs.
		newNode.Children[idx] = leftSubtree // leftSubtree should be at idx. It contains the things lexically before than our new key.
		newNode.Children = append(newNode.Children, NodeHash{}) // Append an empty space to the children.
		copy(newNode.Children[idx+2:], newNode.Children[idx+1:]) // Shift everything starting from idx+1 to one right. Make space for rightSubtree.
		newNode.Children[idx+1] = rightSubtree // Insert the rightSubtree. It contains sub entries with lexically higher keys than our new key (currently at idx), but lexically lower keys than the entry that was previously at idx but now at idx+1.

		err = t.store.Delete(nodeHash) // newNode will have a different hash and nodeHash is not needed anymore. We delete it.
		if err != nil {return NodeHash{}, err}

		return t.store.Put(newNode) // Put our new node to the store and return it's new NodeHash. The parent node will update the child to the new NodeHash using the returned value.
	}

	// If the new entry we wanna insert has a lower level, we need to recurse down and insert it at lower levels.
	// And update new node hashes until to the top.

	numEntries := len(node.Entries)/2
	// We get the index of the entry with a TID lexically higher than our new key.
	idx := sort.Search(numEntries, func(i int) bool {
		return bytes.Compare(node.TID(i), tid) >= 0
	})

	// This idx also responds to the node that holds sub entries with our TID's lexical range. We need to insert it there.
	newChildNodeHash, err := t.insert(node.Children[idx], tid, cid, entryLevel)
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
func (t *Tree) split(nodeHash NodeHash, tid []byte) (NodeHash, NodeHash, error) {
	if len(nodeHash) == 0 { return NodeHash{}, NodeHash{}, nil } // If nodeHash is empty, we return two empty subtrees.

	node, err := t.store.Get(nodeHash) // Get the node with given ID.
	if err != nil { return NodeHash{}, NodeHash{}, err }

	numEntries := len(node.Entries) / 2
	// Look for a node index higher than or equal to our key. This index and things after that should be at the right tree.
	// Others should be at the left tree. Left tree is for entries with lexically lower keys than the key passed as an argument.
	idx := sort.Search(numEntries, func(i int) bool {
		return bytes.Compare(node.TID(i), tid) >= 0
	})

	flat := extractEntries(node.Entries)

	// Create two new nodes with our old node's level.
	leftNode := &Node{Level: node.Level}
	rightNode := &Node{Level: node.Level}

	// Insert the entries and children until idx to the left node.
	leftNode.Entries = compressFlatEntries(flat[:2*idx])
	leftNode.Children = append([]NodeHash(nil), node.Children[:idx]...)

	// Insert the entries from idx to the end to the right node.
	rightNode.Entries = compressFlatEntries(flat[2*idx:])
	// Insert children nodes from idx+1 to the end to the right node.
	rightNode.Children = append([]NodeHash(nil), node.Children[idx+1:]...)

	// The logic for the node at the idx is different.
	// This node was holding entries with keys higher than left node's last entry but lower than right node's first entry.
	// Meaning, it contains things in left and right of our key. So we need to split it into two parts too.
	// This process is recursive, because it's also true for lower level nodes. Left and right parts are sharing one common middle node which needs to be splitted to lexically lower and higher parts until the end.
	boundaryChild := node.Children[idx]
	leftSubChild, rightSubChild, err := t.split(boundaryChild, tid) // This saves left and right subchild to the store and returns their NodeHash.
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

// Delete() deletes a TID/CID entry from the tree by applying a reverse logic of insertion.
func (t *Tree) Delete(tid []byte) error {
	// Call the actual recursive function and get the resulting new root hash
	newRoot, err := t.delete(t.rootNodeHash, tid)
	if err != nil {return err}

	t.rootNodeHash = newRoot // Update the tree's root with the new hash.
	return nil
}
func (t *Tree) delete(nHash NodeHash, tid []byte) (NodeHash, error) {
	if len(nHash) == 0 {return nil, nil} // When nHash becomes empty, it means we reached to the bottom.

	// Get the node with nHash
	node, err := t.store.Get(nHash)
	if err!=nil  {return nil, err}

	numEntries := len(node.Entries)/2

	// Get the index of the key in the current node's entries
	// or if it does not exists, get the index of the next element with lexically higher key.
	// if there is no lexically higher key, return the length of the entries slice. Which is the same with the last child node's index.
	idx := sort.Search(numEntries, func(i int) bool {
		return bytes.Compare(node.TID(i), tid) >= 0
	})

	newNode := node.Clone() // Deep copy node to newNode. We will modify it.

	// Analyze the blocks inside if/else, and you are good to go! Write the test files and sql adapter, and boom!

	// If the entry with TID is found in the current node
	if idx < numEntries && bytes.Equal(node.TID(idx), tid) {

		// As we delete this key, we need to merge the two child subtrees separated by this key.
		mergedChild, err := t.merge(newNode.Children[idx], newNode.Children[idx+1])
		if err != nil { return nil, err }

		// After that, we remove the entry from entries.
		flat := extractEntries(newNode.Entries)
		flat = append(flat[:2*idx], flat[2*idx+2:]...)
		newNode.Entries = compressFlatEntries(flat)

		// And we replace the two child nodes (left and right of key) with the merged child.
		newNode.Children = append(newNode.Children[:idx], newNode.Children[idx+1:]...)
		newNode.Children[idx] = mergedChild

		// If this node becomes empty as a result of deletion, it should be ignored and we should return the child of it instead of this node.
		if numEntries == 0 {
			err = t.store.Delete(nHash)
			if err != nil { return nil, err }
			return mergedChild, nil
		}

	// IF the key is not in this node, recurse down to the correct child.
	} else {

		// If the key is not in this node, recurse down to the child node with the same boundary.
		newChildHash, err := t.delete(newNode.Children[idx], tid)
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
		leftFlat := extractEntries(leftNode.Entries)
		rightFlat := extractEntries(rightNode.Entries)
		combinedFlat := append(leftFlat, rightFlat...)
		newNode.Entries = compressFlatEntries(combinedFlat)

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
