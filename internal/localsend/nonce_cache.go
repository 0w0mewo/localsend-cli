package localsend

import (
	"container/list"
	"sync"
)

// NonceCache implements a thread-safe LRU cache for storing client nonces.
// Used in v3 protocol to cache nonces exchanged during authentication.
type NonceCache struct {
	capacity int
	mu       sync.Mutex
	cache    map[string]*list.Element
	lru      *list.List
}

// cacheEntry represents an entry in the LRU cache.
type cacheEntry struct {
	clientID string
	nonce    []byte
}

// NewNonceCache creates a new NonceCache with the specified capacity.
// When the cache exceeds capacity, the least recently used entry is evicted.
func NewNonceCache(capacity int) *NonceCache {
	return &NonceCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Put stores a nonce for the given clientID.
// If the clientID already exists, its nonce is updated and moved to the front.
// If the cache is at capacity, the least recently used entry is evicted.
func (nc *NonceCache) Put(clientID string, nonce []byte) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// If entry exists, update it and move to front
	if elem, exists := nc.cache[clientID]; exists {
		nc.lru.MoveToFront(elem)
		elem.Value.(*cacheEntry).nonce = nonce
		return
	}

	// Add new entry
	entry := &cacheEntry{
		clientID: clientID,
		nonce:    nonce,
	}
	elem := nc.lru.PushFront(entry)
	nc.cache[clientID] = elem

	// Evict oldest if over capacity
	if nc.lru.Len() > nc.capacity {
		oldest := nc.lru.Back()
		if oldest != nil {
			nc.lru.Remove(oldest)
			delete(nc.cache, oldest.Value.(*cacheEntry).clientID)
		}
	}
}

// Get retrieves the nonce for the given clientID.
// Returns the nonce and true if found, nil and false otherwise.
// Accessing an entry moves it to the front (most recently used).
func (nc *NonceCache) Get(clientID string) ([]byte, bool) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	elem, exists := nc.cache[clientID]
	if !exists {
		return nil, false
	}

	nc.lru.MoveToFront(elem)
	return elem.Value.(*cacheEntry).nonce, true
}
