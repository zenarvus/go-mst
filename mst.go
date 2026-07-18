package main

// TODO: This should just store CID of posts for verification. That's all.
// TODO: Use generics for entries? It would be much more flexible.
// TODO: Change CID with nodeHash. It's easier to get and follow around. Also make it []byte
// TODO: Implement deletion from the tree!!! It's the reverse logic of everything.
// TODO: "a" is lexically lower than "b". And comes before than b. If there is a mistake in the comments, fix it.
// TODO: Also implement the deletion of old nodes with old CIDs. Or our store will get bloated with unnecessary stuff.
// TODO: Convert this to a library.

import (
	"bytes"
	"math/bits"
	"sort"

	"github.com/zenarvus/compack/go"
	"github.com/zenarvus/polyformats/polysha/go"
)

// Compack is used to hash nodes in a canonical form.
var cmpck = compack.NewCompackHandler(&compack.Options{Canonical:true})

// CID represents a cryptographic Content Identifier (the hash of a node). We use it to get nodes from the store.
type CID string

// Entry represents a key-value pair stored inside a node.
type Entry struct {
	Key   []byte
	Value []byte // Remove value. We only need keys.
}

// Node represents a single block in the Merkle Search Tree.
type Node struct {
	Level    int     `cmpck:"1"`
	Entries  []Entry `cmpck:"2"` // Entries are the actual key/value pairs.
	Children []CID   `cmpck:"3"` // Length is always len(Entries) + 1. Children are sub nodes.
}

// Clone creates a deep copy of a node to preserve immutability.
func (n *Node) Clone() *Node {
	if n == nil { return nil }

	cloned := &Node{
		Level:    n.Level,
		Entries:  make([]Entry, len(n.Entries)),
		Children: make([]CID, len(n.Children)),
	}

	copy(cloned.Entries, n.Entries)
	copy(cloned.Children, n.Children)

	return cloned
}

func (n *Node) isEmpty() bool {
	if len(n.Entries) > 0 { return false } // If there are sub entries, node is not empty.

	// If there is a child node with an non-empty cid, node is not empty.
	for _, child := range n.Children {
		if child != "" { return false }
	}

	// Else, node is empty.
	return true
}

// Tree represents the Merkle Search Tree wrapper.
type Tree struct {
	store BlockStore
	root  CID
}

func NewTree(store BlockStore) *Tree {
	return &Tree{store: store, root: ""}
}

// Return the root CID of the tree.
func (t *Tree) Root() CID { return t.root }

// Get searches for a key in the tree.
func (t *Tree) Get(key []byte) ([]byte, error) {
	return t.get(t.root, key) // Start from the root.
}

func (t *Tree) get(nodeCID CID, key []byte) ([]byte, error) {
	if nodeCID == "" { return nil, nil } // Key not found

	// How this gonna get apple that comes before banana but in a lower level? (assume word length determines the level).
	// - Oh, banana is the first element and is higher than the apple. It's index is 0, so returned idx will be 0. (Key is not equal to banana so we will traverse down)
	// - Apple is in the first child node which also has an idx of 0.
	//
	// What about grape? It's after cherry and in a lower level.
	// - Then, every key in the current node entries will be lower than it. As the sort.Search won't find anything, it will return len(node.Entries), which is equal to the idx of the child node that contains grape. We will traverse down to the node to that node and find it.

	node, err := t.store.Get(nodeCID) // Find the node with given CID in the store.
	if err != nil { return nil, err }

	// sort.Search binary searches and returns an index in a given sorted slice.
	idx := sort.Search(len(node.Entries), func(i int)bool{
		// This index is the index of the entry with a key bigger than or similar with the given key.
		return bytes.Compare(node.Entries[i].Key, key) >= 0
		// Meaning, if the key exists, it returns it's index. If it does not exist, it returns the index of the key bigger than given key.
	})

	// If index is within the range of slice, and the key with that index in the entries match with the given key
	if idx < len(node.Entries) && bytes.Equal(node.Entries[idx].Key, key) {
		// Return the value of that key
		return node.Entries[idx].Value, nil
	}

	// Else, search for this key's value in the children with the index we found. Because if the key does not exist in the current node's entries, we need to traverse the tree down.
	// As the entry with key does not exist in the current node entries, idx is the index of the key bigger than the given key.
	// Children nodes store the sub entries with keys that come after the entry with idx in the current node.
	return t.get(node.Children[idx], key)
}

// Insert adds or updates a key-value pair in the tree.
func (t *Tree) Insert(key, value []byte) error {
	// We determine the level of the key by counting the leading zeros in it's hash.
	level,err := determineLevel(key, t.store.HashAlgorithm())
	if err!=nil{return err}

	// Then we insert it in the given level. We start from root for looking, and traverse down.
	newRoot, err := t.insert(t.root, key, value, level)
	if err != nil { return err }

	// We get the new root and update the current one with that.
	t.root = newRoot
	return nil
}

func (t *Tree) insert(nodeCID CID, key, value []byte, keyLevel int) (CID, error) {
	// If node with this CID does not exist, we create one and assign it the keyLevel.
	// We put our key/value there and create two empty child nodes.
	if nodeCID == "" {
		newNode := &Node{
			Level:    keyLevel,
			Entries:  []Entry{{Key: key, Value: value}},
			Children: []CID{"", ""},
		}
		return t.store.Put(newNode) // Calculate node's canonical hash and put to the store with that CID. Then, return that CID.
		// We use returned CID to update the parent node's previously empty children CID. (The one had nodeCID). The logic of it is below.
		// Or if the tree was empty, (thus t.root was empty) nodeCID will be empty and this node will be the parent node. And it's becomes the root CID.
	}

	// If nodeCID is not empty, we get it from the store.
	node, err := t.store.Get(nodeCID)
	if err != nil { return "", err }

	// If the key we wanna insert has a higher level than the node we get, it must be in a newNode that is parent of node with nodeCID.
	// We use t.split function for that. It splits nodeCID and it's entire subtree in half.
	if keyLevel > node.Level {
		leftSubtree, rightSubtree, err := t.split(nodeCID, key)
		if err != nil { return "", err }

		// Then create a new parent node with our higher keyLevel and insert our key in there.
		// leftSubtree contains the keys lexically comes before our key.
		// rightSubtree contains the keys lexically comes after our key.
		newNode := &Node{
			Level:    keyLevel,
			Entries:  []Entry{{Key: key, Value: value}},
			Children: []CID{leftSubtree, rightSubtree},
		}
		return t.store.Put(newNode) // Then we insert our new node and return it's CID.
	}

	// If the new key has the same level with the node we found (one with nodeCID), we need to insert it in there.
	if keyLevel == node.Level {
		// Find the index of an entry in the node. An entry with a key that is higher or equal to our key.
		idx := sort.Search(len(node.Entries), func(i int) bool {
			return bytes.Compare(node.Entries[i].Key, key) >= 0
		})

		// If entry/key already exists, we simply update its value.
		if idx < len(node.Entries) && bytes.Equal(node.Entries[idx].Key, key) {
			newNode := node.Clone()
			newNode.Entries[idx].Value = value
			return t.store.Put(newNode)
		}

		// If the new entry does not exist in the current node, we use the logic below.

		// We split the child node at idx using our new key.
		// idx is the index of the entry with a key lexically higher than our key.
		// This idx also the node that contains sub entries that with lexically lower and higher keys than our new entry's key. (but this node's entries are lexically before than the node currently at idx)
		// So we need to split that node.
		leftSubtree, rightSubtree, err := t.split(node.Children[idx], key)
		if err != nil { return "", err }

		newNode := node.Clone() // Clone the nodeCID node.

		// We need to place our new key to the idx and shift everything after that to the right.
		// Because it's key is lexically higher than the entry in idx-1 but lexically lower than the entry at idx.
		newNode.Entries = append(newNode.Entries, Entry{}) // Append a new entry to the node.
		copy(newNode.Entries[idx+1:], newNode.Entries[idx:]) // Copy everything from idx to the end to idx+1 to the end. Which shifts everything to right and empties the entry at idx. (First argument is the destination and the second is the source. Not vice versa)
		newNode.Entries[idx] = Entry{Key: key, Value: value} // Then we insert our new entry to idx.

		// We also need to shift the sub nodes to one right and insert our new sub node where it belongs.

		newNode.Children[idx] = leftSubtree // leftSubtree should be at idx. It contains the things lexically before than our new key.
		newNode.Children = append(newNode.Children, "") // Append an empty space to the children.
		copy(newNode.Children[idx+2:], newNode.Children[idx+1:]) // Shift everything starting from idx+1 to one right. Make space for rightSubtree.
		newNode.Children[idx+1] = rightSubtree // Insert the rightSubtree. It contains sub entries with lexically higher keys than our new key (currently at idx), but lexically lower keys than the entry that was previously at idx but now at idx+1.

		return t.store.Put(newNode) // Put our new node to the store and return it's new CID. The parent node will update the child to the new CID using the returned value.
	}

	// If the new key we wanna insert has a lower level, we need to recurse down and insert it at lower levels.

	// We get the index of the entry with a key lexically higher than our new key.
	idx := sort.Search(len(node.Entries), func(i int) bool {
		return bytes.Compare(node.Entries[i].Key, key) >= 0
	})

	// This idx also responds to the node that holds sub entries with our key's lexical range. We need to insert it there.
	newChildCID, err := t.insert(node.Children[idx], key, value, keyLevel)
	if err != nil { return "", err }

	// After the insertion, we get the new calculated nodeHash of the node at node.Children[idx]

	newNode := node.Clone() // Clone the node and its entries and children nodeHash addresses.
	newNode.Children[idx] = newChildCID // Update the child node's nodeHash with the new nodeHash address.
	return t.store.Put(newNode) // Put our new node to the store.
}

// Finish this and i am done!!! (i need to analyze proof part too, but i will simply .gitignore it for now)

// split divides a subtree into two subtrees around a split key.
func (t *Tree) split(nodeCID CID, key []byte) (CID, CID, error) {
	if nodeCID == "" { return "", "", nil } // If nodeCID is empty, we return two empty subtrees.

	node, err := t.store.Get(nodeCID) // Get the node with given ID.
	if err != nil { return "", "", err }

	// Look for a node index higher than or equal to our key. This index and things after that should be at the right tree.
	// Others should be at the left tree. Left tree is for entries with lexically lower keys than the key passed as an argument.
	idx := sort.Search(len(node.Entries), func(i int) bool {
		return bytes.Compare(node.Entries[i].Key, key) >= 0
	})

	// Create two new nodes with our old node's level.
	leftNode := &Node{Level: node.Level}
	rightNode := &Node{Level: node.Level}

	// Insert the entries and children until idx to the left node.
	leftNode.Entries = append([]Entry(nil), node.Entries[:idx]...)
	leftNode.Children = append([]CID(nil), node.Children[:idx]...)

	// Insert the entries from idx to the end to the right node.
	rightNode.Entries = append([]Entry(nil), node.Entries[idx:]...)

	// Insert children nodes from idx+1 to the end to the right node.
	rightNode.Children = append([]CID(nil), node.Children[idx+1:]...)

	// The logic for the node at the idx is different.
	// This node was holding entries with keys higher than left node's last entry but lower than right node's first entry.
	// Meaning, it contains things in left and right of our key. So we need to split it into two parts too.
	// This process is recursive, because it's also true for lower level nodes. Left and right parts are sharing one common middle node which needs to be splitted to lexically lower and higher parts until the end.
	boundaryChild := node.Children[idx]
	leftSubChild, rightSubChild, err := t.split(boundaryChild, key) // This saves left and right subchild to the store and returns their cid.
	if err != nil { return "", "", err }

	// Add leftSubChild to the leftNode's children. (to the end)
	leftNode.Children = append(leftNode.Children, leftSubChild)
	// Add rightSubChild to the rightNode's children. (to the start)
	rightNode.Children = append([]CID{rightSubChild}, rightNode.Children...)

	// Insert left and right nodes to the store and get their nodeHash addresses.
	var leftCID, rightCID CID
	if !leftNode.isEmpty() {
		leftCID, err = t.store.Put(leftNode)
		if err != nil { return "", "", err }
	}
	if !rightNode.isEmpty() {
		rightCID, err = t.store.Put(rightNode)
		if err != nil { return "", "", err }
	}

	// Finally, return those nodes' nodeHash addresses.
	return leftCID, rightCID, nil
}

// determineLevel calculates a deterministic level based on leading bits of a SHA-256 hash.
func determineLevel(key []byte, hashAlgorithm polysha.SHAType) (int,error) {
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
