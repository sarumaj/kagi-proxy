package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sarumaj/kagi-proxy/pkg/api/templates"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// visitor replays one browser: it keeps the proxy session cookie across requests, which is
// what makes a thread claim stick.
type visitor struct {
	router *gin.Engine
	cookie *http.Cookie
}

func (v *visitor) get(path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "kagi.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if v.cookie != nil {
		req.AddCookie(v.cookie)
	}

	recorder := httptest.NewRecorder()
	v.router.ServeHTTP(recorder, req)

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "proxy_session" {
			v.cookie = cookie
		}
	}

	return recorder.Code
}

// newVisitor signs a browser in by handing it a session with a session id of its own.
func newVisitor(t *testing.T, router *gin.Engine, sessionID string) *visitor {
	t.Helper()

	v := &visitor{router: router}
	if code := v.get("/signin?session_id=" + sessionID); code != http.StatusOK {
		t.Fatalf("sign in returned %d", code)
	}

	return v
}

// TestThreadGuard pins the isolation between the proxy users. Every assistant thread lives
// in the one kagi.com account the proxy shares, so without the guard any user could open
// any other user's thread by its address alone.
func TestThreadGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)

	common.SetSessionToken("token")
	common.SetProxySessionDuration(30 * 24 * time.Hour)
	common.SetProxyTargetHosts(common.HostMap{"kagi.example.com": "kagi.com"})
	common.SetProxyPublicDomains(common.Domains{"help.kagi.example.com"})
	common.SetProxyPrivateThreads(true)

	router := gin.New(func(e *gin.Engine) {
		e.SetHTMLTemplate(templates.HTMLTemplates())
		e.Use(Session())
	})
	router.GET("/signin", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Set("user", "owner")
		session.Set("session_id", ctx.Query("session_id"))
		if err := session.Save(); err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	})
	router.NoRoute(ThreadGuard(), func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	owner := newVisitor(t, router, "session-"+uuid.NewString())
	other := newVisitor(t, router, "session-"+uuid.NewString())

	threadID := uuid.NewString()

	// Opening a thread nobody holds claims it: this is the request the assistant makes for
	// the thread the user has just created.
	if code := owner.get("/chat/" + threadID); code != http.StatusOK {
		t.Fatalf("owner opening a new thread got %d, want %d", code, http.StatusOK)
	}

	// The claim survives, so the owner keeps reaching the thread and its API routes.
	for _, path := range []string{"/chat/" + threadID, "/api/assistant/thread/" + threadID + "/messages"} {
		if code := owner.get(path); code != http.StatusOK {
			t.Errorf("owner requesting %s got %d, want %d", path, code, http.StatusOK)
		}
	}

	// Knowing the address is not enough for anybody else, on the page route or behind it.
	for _, path := range []string{"/chat/" + threadID, "/api/assistant/thread/" + threadID + "/messages"} {
		if code := other.get(path); code != http.StatusForbidden {
			t.Errorf("second session requesting %s got %d, want %d", path, code, http.StatusForbidden)
		}
	}

	// Threads of its own remain unaffected, and so does everything that is not a thread.
	if code := other.get("/chat/" + uuid.NewString()); code != http.StatusOK {
		t.Errorf("second session opening its own thread got %d, want %d", code, http.StatusOK)
	}
	if code := other.get("/settings/assistant"); code != http.StatusOK {
		t.Errorf("second session requesting an unrelated page got %d, want %d", code, http.StatusOK)
	}
}

// TestThreadGuardDisabled checks the kill switch: with the isolation off the proxy hands
// out every thread again, the way it did before threads were scoped to a session.
func TestThreadGuardDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	common.SetSessionToken("token")
	common.SetProxySessionDuration(30 * 24 * time.Hour)
	common.SetProxyTargetHosts(common.HostMap{"kagi.example.com": "kagi.com"})
	common.SetProxyPrivateThreads(false)
	defer common.SetProxyPrivateThreads(true)

	router := gin.New(func(e *gin.Engine) {
		e.SetHTMLTemplate(templates.HTMLTemplates())
		e.Use(Session())
	})
	router.GET("/signin", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Set("user", "owner")
		session.Set("session_id", ctx.Query("session_id"))
		if err := session.Save(); err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	})
	router.NoRoute(ThreadGuard(), func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	owner := newVisitor(t, router, "session-"+uuid.NewString())
	other := newVisitor(t, router, "session-"+uuid.NewString())

	threadID := uuid.NewString()
	if code := owner.get("/chat/" + threadID); code != http.StatusOK {
		t.Fatalf("owner opening a thread got %d, want %d", code, http.StatusOK)
	}

	if code := other.get("/chat/" + threadID); code != http.StatusOK {
		t.Errorf("second session got %d with the isolation disabled, want %d", code, http.StatusOK)
	}
}
