package endpoints

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sarumaj/kagi-proxy/pkg/common"
)

// TestClaimThread pins the rules of the route the injected script reports a newly created
// thread on. It is the one place a user names a thread id themselves, so it may only ever
// hand out a thread nobody holds.
func TestClaimThread(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New(func(e *gin.Engine) {
		e.Use(sessions.Sessions("proxy_session", cookie.NewStore(common.MakeKeyPair([]byte("test")))))
	})
	router.GET("/signin", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Set("session_id", ctx.Query("session_id"))
		if err := session.Save(); err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	})
	router.POST(ThreadClaimPath, ClaimThread)

	// signIn returns the session cookie of a freshly authenticated browser.
	signIn := func(sessionID string) *http.Cookie {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/signin?session_id="+sessionID, nil))
		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == "proxy_session" {
				return cookie
			}
		}

		t.Fatalf("sign in did not set a session cookie")
		return nil
	}

	claim := func(session *http.Cookie, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, ThreadClaimPath, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", gin.MIMEJSON)
		if session != nil {
			req.AddCookie(session)
		}

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	owner, other := signIn("session-"+uuid.NewString()), signIn("session-"+uuid.NewString())
	threadID := uuid.NewString()

	recorder := claim(owner, `{"thread_id":"`+threadID+`"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("claiming a new thread got %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload struct {
		Threads []string `json:"threads"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode the response: %v", err)
	}
	if len(payload.Threads) != 1 || payload.Threads[0] != threadID {
		t.Errorf("response listed %v, want [%s]", payload.Threads, threadID)
	}

	for _, tt := range []struct {
		name    string
		session *http.Cookie
		body    string
		want    int
	}{
		{name: "a thread another session holds", session: other, body: `{"thread_id":"` + threadID + `"}`, want: http.StatusForbidden},
		{name: "a value that is not a thread id", session: other, body: `{"thread_id":"kagi"}`, want: http.StatusBadRequest},
		{name: "no thread id at all", session: other, body: `{}`, want: http.StatusBadRequest},
		{name: "no session", session: nil, body: `{"thread_id":"` + uuid.NewString() + `"}`, want: http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if code := claim(tt.session, tt.body).Code; code != tt.want {
				t.Errorf("claiming %s got %d, want %d", tt.name, code, tt.want)
			}
		})
	}
}
