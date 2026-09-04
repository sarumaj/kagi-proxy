package common

import (
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// maxSessionThreads caps how many thread ids a single session carries. The set travels in
// the proxy's own cookie and a browser discards a cookie larger than 4 KB, so the budget is
// what matters here: 64 ids are 1 KB of packed binary, which still fits once the store has
// encrypted and base64-encoded the whole session. Past the cap the oldest id is evicted, so
// a heavy user loses their oldest threads rather than the one they are working in.
const maxSessionThreads = 64

// threadsSessionKey is the session key the packed thread ids live under.
const threadsSessionKey = "threads"

// threadPruneInterval is how often the registry sweeps expired claims. Sweeping on every
// claim would walk the whole map on every thread request for no gain, since an entry only
// expires once its session could no longer present it.
const threadPruneInterval = 10 * time.Minute

// uuidExpr matches the canonical text form of the identifiers kagi.com mints for assistant
// threads. It is shared with the injected script, which applies it to location.pathname.
const uuidExpr = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

var (
	// threadPathPattern matches the page routes that open a single assistant thread: the
	// current /chat/<id> spelling and the older /assistant/<id> one.
	threadPathPattern = regexp.MustCompile(`^/(?:chat|assistant)/(` + uuidExpr + `)(?:/.*)?$`)

	// threadIDPattern matches a thread id anywhere in a path, which is how the API routes
	// behind the page (.../thread/<id>, .../<id>/messages, ...) carry it.
	threadIDPattern = regexp.MustCompile(uuidExpr)

	threadOwners = &ThreadRegistry{
		owners:   map[string]threadOwner{},
		restored: map[string]time.Time{},
	}
)

type (
	// ThreadRegistry records which proxy session owns which assistant thread.
	//
	// Every thread belongs to the one kagi.com account the proxy shares, so the target host
	// cannot tell the proxy users apart and the distinction only exists here. The registry
	// is kept in memory: a claim lives as long as the process does and is restored from the
	// session cookie afterwards, which the proxy signs and encrypts itself and which is
	// therefore no less trustworthy than the map.
	ThreadRegistry struct {
		mutex     sync.Mutex
		owners    map[string]threadOwner
		restored  map[string]time.Time
		lastPrune time.Time
	}

	// threadOwner is the session a thread belongs to, and when that was last confirmed.
	threadOwner struct {
		session string
		seen    time.Time
	}
)

// Threads returns the process-wide thread ownership registry.
func Threads() *ThreadRegistry { return threadOwners }

// Claim records sessionID as the owner of threadID and reports whether that session owns
// the thread once the call returns.
//
// An unclaimed thread falls to whoever reaches it first, which in practice is the session
// that created it: thread ids are random, and a user never sees one belonging to somebody
// else because the listing hides them. The alternative, recognising the creating request
// itself, would require the proxy to model an upstream API it does not control.
func (r *ThreadRegistry) Claim(threadID, sessionID string) bool {
	if len(threadID) == 0 || len(sessionID) == 0 {
		return false
	}

	key := strings.ToLower(threadID)

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.prune()

	if owner, ok := r.owners[key]; ok && owner.session != sessionID {
		return false
	}

	r.owners[key] = threadOwner{session: sessionID, seen: time.Now()}
	return true
}

// Owner returns the session owning the thread, and whether the thread is claimed at all.
func (r *ThreadRegistry) Owner(threadID string) (string, bool) {
	if len(threadID) == 0 {
		return "", false
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	owner, ok := r.owners[strings.ToLower(threadID)]
	return owner.session, ok
}

// Restore re-asserts the claims a session carries in its cookie, once per session and
// process. It only fills gaps: a thread another session has claimed in the meantime stays
// with that session, so restarting the proxy cannot be used to take a thread over.
func (r *ThreadRegistry) Restore(sessionID string, threadIDs []string) {
	if len(sessionID) == 0 {
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.prune()

	if _, ok := r.restored[sessionID]; ok {
		return
	}
	r.restored[sessionID] = time.Now()

	for _, threadID := range threadIDs {
		key := strings.ToLower(threadID)
		if owner, ok := r.owners[key]; ok {
			if owner.session != sessionID {
				Logger().Warn("Thread claimed by another session since the last restart",
					zap.String("thread", key))
			}
			continue
		}

		r.owners[key] = threadOwner{session: sessionID, seen: time.Now()}
	}
}

// prune drops the claims that can no longer be presented by any session. The caller holds
// the mutex.
func (r *ThreadRegistry) prune() {
	now := time.Now()
	if now.Sub(r.lastPrune) < threadPruneInterval {
		return
	}
	r.lastPrune = now

	ttl := ConfigProxySessionDuration()
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}

	cutoff := now.Add(-ttl)
	for threadID, owner := range r.owners {
		if owner.seen.Before(cutoff) {
			delete(r.owners, threadID)
		}
	}

	for sessionID, seen := range r.restored {
		if seen.Before(cutoff) {
			delete(r.restored, sessionID)
		}
	}
}

// NormalizeThreadID returns the canonical form of a thread id, and whether the input was
// shaped like one at all.
func NormalizeThreadID(threadID string) (string, bool) {
	parsed, err := uuid.Parse(threadID)
	if err != nil {
		return "", false
	}

	return parsed.String(), true
}

// ThreadIDFromPath returns the id of the thread a page route opens.
func ThreadIDFromPath(path string) (string, bool) {
	match := threadPathPattern.FindStringSubmatch(path)
	if match == nil {
		return "", false
	}

	return strings.ToLower(match[1]), true
}

// ThreadIDsInPath returns every thread-shaped id the path carries, page route or not.
func ThreadIDsInPath(path string) []string {
	found := threadIDPattern.FindAllString(path, -1)
	for i, threadID := range found {
		found[i] = strings.ToLower(threadID)
	}

	return found
}

// ThreadPathPattern returns the regular expression for thread page routes. The proxy and
// the injected script have to agree on it: the script recognises the client-side
// navigation that creates a thread, the proxy authorizes the requests that follow.
func ThreadPathPattern() string { return threadPathPattern.String() }

// SessionThreads returns the threads the session owns, oldest first.
func SessionThreads(session sessions.Session) []string {
	packed := QuickGet[string](session, threadsSessionKey)
	if len(packed) == 0 {
		return nil
	}

	decoded, err := B64URLNoPadding.DecodeString(packed)
	if err != nil {
		Logger().Warn("Discarding unreadable thread set from session", zap.Error(err))
		return nil
	}

	threadIDs := make([]string, 0, len(decoded)/len(uuid.UUID{}))
	for len(decoded) >= len(uuid.UUID{}) {
		var threadID uuid.UUID
		copy(threadID[:], decoded)
		threadIDs = append(threadIDs, threadID.String())
		decoded = decoded[len(uuid.UUID{}):]
	}

	return threadIDs
}

// SessionAddThread adds a thread to the session and reports whether the session changed
// and has to be saved. Ids are stored in their 16-byte binary form rather than as text,
// which is what keeps maxSessionThreads of them inside the cookie budget.
func SessionAddThread(session sessions.Session, threadID string) bool {
	normalized, ok := NormalizeThreadID(threadID)
	if !ok {
		return false
	}

	threadIDs := SessionThreads(session)
	if slices.Contains(threadIDs, normalized) {
		return false
	}

	threadIDs = append(threadIDs, normalized)
	if len(threadIDs) > maxSessionThreads {
		threadIDs = threadIDs[len(threadIDs)-maxSessionThreads:]
	}

	packed := make([]byte, 0, len(threadIDs)*len(uuid.UUID{}))
	for _, threadID := range threadIDs {
		parsed, err := uuid.Parse(threadID)
		if err != nil {
			continue
		}

		packed = append(packed, parsed[:]...)
	}

	session.Set(threadsSessionKey, B64URLNoPadding.EncodeToString(packed))
	return true
}
