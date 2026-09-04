package common

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/google/uuid"
)

// stubSession is the part of sessions.Session the thread helpers touch.
type stubSession struct {
	sessions.Session
	values map[string]any
}

func (s *stubSession) Get(key any) any        { return s.values[key.(string)] }
func (s *stubSession) Set(key any, value any) { s.values[key.(string)] = value }

// TestThreadIDFromPath pins which routes count as opening a thread. Only a page route may
// claim one, so a match here is what hands ownership to the session making the request.
func TestThreadIDFromPath(t *testing.T) {
	const threadID = "827a06ed-17dd-4b6f-af3c-345dceec19f8"

	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{name: "current spelling", path: "/chat/" + threadID, want: threadID},
		{name: "legacy spelling", path: "/assistant/" + threadID, want: threadID},
		{name: "sub route of a thread", path: "/chat/" + threadID + "/share", want: threadID},
		{name: "upper case id is normalized", path: "/chat/" + strings.ToUpper(threadID), want: threadID},
		{name: "api route does not claim", path: "/api/thread/" + threadID, want: ""},
		{name: "unrelated route", path: "/settings/assistant", want: ""},
		{name: "thread listing", path: "/assistant", want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ThreadIDFromPath(tt.path)
			if ok != (len(tt.want) > 0) || got != tt.want {
				t.Errorf("ThreadIDFromPath(%q) = (%q, %t), want %q", tt.path, got, ok, tt.want)
			}
		})
	}
}

// TestThreadIDsInPath covers the ids the guard has to recognize beyond the page routes:
// the API calls behind a thread carry the same id and must be answered the same way.
func TestThreadIDsInPath(t *testing.T) {
	const threadID = "827a06ed-17dd-4b6f-af3c-345dceec19f8"

	if got := ThreadIDsInPath("/api/assistant/thread/" + strings.ToUpper(threadID) + "/messages"); len(got) != 1 || got[0] != threadID {
		t.Errorf("ThreadIDsInPath() = %v, want [%s]", got, threadID)
	}

	if got := ThreadIDsInPath("/settings/assistant"); len(got) != 0 {
		t.Errorf("ThreadIDsInPath() = %v, want none", got)
	}
}

// TestSessionThreadsRoundTrip checks that the packed representation survives the trip
// through the session and stays within the cookie budget, which is what the eviction is
// there to guarantee.
func TestSessionThreadsRoundTrip(t *testing.T) {
	session := &stubSession{values: map[string]any{}}

	var added []string
	for i := 0; i < maxSessionThreads+10; i++ {
		threadID := uuid.New().String()
		added = append(added, threadID)
		if !SessionAddThread(session, threadID) {
			t.Fatalf("SessionAddThread(%s) did not change the session", threadID)
		}
	}

	// Adding a thread twice must not grow the set, or a reload would evict the oldest
	// threads for nothing.
	if SessionAddThread(session, added[len(added)-1]) {
		t.Error("SessionAddThread() reported a change for a thread the session already owns")
	}

	if SessionAddThread(session, "not-a-uuid") {
		t.Error("SessionAddThread() accepted a value that is not a thread id")
	}

	stored := SessionThreads(session)
	if len(stored) != maxSessionThreads {
		t.Fatalf("SessionThreads() returned %d ids, want %d", len(stored), maxSessionThreads)
	}

	// The oldest ids are the ones dropped: the thread a user is working in is the newest.
	want := added[len(added)-maxSessionThreads:]
	for i, threadID := range want {
		if stored[i] != threadID {
			t.Errorf("SessionThreads()[%d] = %s, want %s", i, stored[i], threadID)
		}
	}

	if packed := QuickGet[string](session, threadsSessionKey); len(packed) > 3072 {
		t.Errorf("packed thread set is %d bytes, too much of the 4 KB cookie budget", len(packed))
	}
}

// TestThreadRegistry pins the ownership rules: first come, no takeovers, and a restart
// that empties the registry does not let one session inherit another's threads.
func TestThreadRegistry(t *testing.T) {
	registry := &ThreadRegistry{owners: map[string]threadOwner{}, restored: map[string]time.Time{}}

	first, second := uuid.New().String(), uuid.New().String()

	if !registry.Claim(first, "session-a") {
		t.Fatal("Claim() refused an unclaimed thread")
	}

	if !registry.Claim(first, "session-a") {
		t.Error("Claim() refused a thread the session already owns")
	}

	if registry.Claim(first, "session-b") {
		t.Error("Claim() handed a thread to a second session")
	}

	if owner, ok := registry.Owner(first); !ok || owner != "session-a" {
		t.Errorf("Owner() = (%q, %t), want session-a", owner, ok)
	}

	if _, ok := registry.Owner(second); ok {
		t.Error("Owner() reported an owner for an unclaimed thread")
	}

	// A restored cookie fills the gaps a restart left, but never takes a thread away from
	// the session that claimed it in the meantime.
	registry.Restore("session-b", []string{first, second})
	if owner, _ := registry.Owner(first); owner != "session-a" {
		t.Errorf("Restore() reassigned a claimed thread to %q", owner)
	}
	if owner, ok := registry.Owner(second); !ok || owner != "session-b" {
		t.Errorf("Restore() did not restore an unclaimed thread, got (%q, %t)", owner, ok)
	}
}
