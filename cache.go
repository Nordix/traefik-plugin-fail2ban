package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"sync"
	"sync/atomic"
	"time"
)

const minWaitTimeBetweenCacheCleans = 10 * time.Minute

// maxTrackedStrikesKeys bounds how many distinct path/status pairs a single
// client entry will track, so a client cycling through URLs cannot grow the
// map without bound.
const maxTrackedStrikesKeys = 32

// Cache implementation for caching of IP entries.
type Cache struct {
	lock        sync.RWMutex
	entries     map[string]*CacheEntry
	lastCleaned atomic.Int64
}

// strikeKey identifies a counted request by sanitized path and response status.
type strikeKey struct {
	Path   string
	Status int
}

// CacheEntry represents single entry/IP in cache.
type CacheEntry struct {
	firstSeen atomic.Int64
	lastSeen  atomic.Int64
	timesSeen atomic.Uint32
	isBanned  atomic.Bool

	strikesLock      sync.Mutex
	strikes          map[strikeKey]uint32
	strikesTruncated bool
}

// SetFirstSeen sets firstSeen.
func (ce *CacheEntry) SetFirstSeen(t time.Time) {
	ce.firstSeen.Store(t.UnixMilli())
}

// GetFirstSeen gets firstSeen.
func (ce *CacheEntry) GetFirstSeen() time.Time {
	return time.UnixMilli(ce.firstSeen.Load())
}

// SetLastSeen sets lastSeen.
func (ce *CacheEntry) SetLastSeen(t time.Time) {
	ce.lastSeen.Store(t.UnixMilli())
}

// GetLastSeen gets lastSeen.
func (ce *CacheEntry) GetLastSeen() time.Time {
	return time.UnixMilli(ce.lastSeen.Load())
}

// IncrementTimesSeen increments timesSeen.
func (ce *CacheEntry) IncrementTimesSeen() {
	ce.timesSeen.Add(1)
}

// GetTimesSeen gets timesSeen.
func (ce *CacheEntry) GetTimesSeen() uint32 {
	return ce.timesSeen.Load()
}

// RecordStrike attributes one strike to a path/status pair and returns the new
// count for that pair. It reports tracked=false once maxTrackedStrikesKeys
// distinct pairs exist, in which case nothing is recorded.
func (ce *CacheEntry) RecordStrike(path string, status int) (count uint32, tracked bool) {
	key := strikeKey{Path: path, Status: status}

	ce.strikesLock.Lock()
	defer ce.strikesLock.Unlock()

	if ce.strikes == nil {
		ce.strikes = make(map[strikeKey]uint32, 8)
	}

	if _, exists := ce.strikes[key]; !exists && len(ce.strikes) >= maxTrackedStrikesKeys {
		ce.strikesTruncated = true

		return 0, false
	}

	ce.strikes[key]++

	return ce.strikes[key], true
}

// getStrikes returns a copy of the strike counters and whether the cap was
// hit. It is unexported because it returns the unexported strikeKey type, and
// nothing outside this package consumes it.
func (ce *CacheEntry) getStrikes() (map[strikeKey]uint32, bool) {
	ce.strikesLock.Lock()
	defer ce.strikesLock.Unlock()

	snapshot := make(map[strikeKey]uint32, len(ce.strikes))
	for key, count := range ce.strikes {
		snapshot[key] = count
	}

	return snapshot, ce.strikesTruncated
}

// IssueBan issues a ban for the entry/ip.
func (ce *CacheEntry) IssueBan() {
	ce.isBanned.Store(true)
}

// IsBanned checks if entry is banned.
func (ce *CacheEntry) IsBanned() bool {
	return ce.isBanned.Load()
}

// NewCache creates new instance of caching.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry, 10000),
	}
}

// GetEntry retrieve entry from cache.
func (c *Cache) GetEntry(key string) *CacheEntry {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.entries[key]
}

// CreateEntry retrieve entry from cache or create new entry with firstSeen.
func (c *Cache) CreateEntry(key string, firstSeen time.Time) *CacheEntry {
	c.lock.Lock()
	defer c.lock.Unlock()

	entry, ok := c.entries[key]
	if ok {
		return entry
	}

	entry = &CacheEntry{}
	entry.SetFirstSeen(firstSeen)
	c.entries[key] = entry

	return entry
}

// CleanEntryIfPossible removes entry from cache by key and limits.
func (c *Cache) CleanEntryIfPossible(key string, findTime, banTime time.Duration, now time.Time) {
	findTimeBoundary := now.Add(-findTime)
	banTimeBoundary := now.Add(-banTime)

	entry := c.GetEntry(key)
	if entry == nil {
		return
	}

	if entry.IsBanned() && entry.GetLastSeen().Before(banTimeBoundary) {
		c.lock.Lock()
		defer c.lock.Unlock()
		delete(c.entries, key)

		return
	}
	if !entry.IsBanned() && entry.GetFirstSeen().Before(findTimeBoundary) {
		c.lock.Lock()
		defer c.lock.Unlock()
		delete(c.entries, key)

		return
	}
}

// CleanEntries garbage collect entries.
func (c *Cache) CleanEntries(findTime, banTime time.Duration) (removedEntries int) {
	lastCleanedRaw := c.lastCleaned.Load()
	lastCleaned := time.UnixMilli(lastCleanedRaw)
	now := time.Now()
	if !lastCleaned.Add(minWaitTimeBetweenCacheCleans).Before(now) {
		// cache was cleaned recently, nothing to do
		return 0
	}
	if !c.lastCleaned.CompareAndSwap(lastCleanedRaw, now.UnixMilli()) {
		// cache is already cleaned by other execution, nothing to do
		return 0
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	findTimeBoundary := now.Add(-findTime)
	banTimeBoundary := now.Add(-banTime)

	for key, entry := range c.entries {
		if !entry.IsBanned() && entry.GetFirstSeen().Before(findTimeBoundary) {
			delete(c.entries, key)
			removedEntries++
		}
	}
	for key, entry := range c.entries {
		if entry.GetLastSeen().Before(banTimeBoundary) {
			delete(c.entries, key)
			removedEntries++
		}
	}

	return removedEntries
}
