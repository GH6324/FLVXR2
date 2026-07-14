package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSSameOriginAndAllowlist(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")
	called := 0
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		origin     string
		host       string
		forwarded  string
		wantStatus int
		wantOrigin string
		wantCalled bool
	}{
		{name: "server request without origin", host: "panel.example.com", wantStatus: http.StatusOK, wantCalled: true},
		{name: "same origin", origin: "http://panel.example.com", host: "panel.example.com", wantStatus: http.StatusOK, wantOrigin: "http://panel.example.com", wantCalled: true},
		{name: "same origin with published proxy port", origin: "http://panel.example.com:63666", host: "panel.example.com:63666", wantStatus: http.StatusOK, wantOrigin: "http://panel.example.com:63666", wantCalled: true},
		{name: "same origin behind https proxy", origin: "https://panel.example.com", host: "panel.example.com", forwarded: "https", wantStatus: http.StatusOK, wantOrigin: "https://panel.example.com", wantCalled: true},
		{name: "configured cross origin", origin: "https://console.example.com", host: "panel.example.com", wantStatus: http.StatusOK, wantOrigin: "https://console.example.com", wantCalled: true},
		{name: "untrusted origin", origin: "https://evil.example", host: "panel.example.com", wantStatus: http.StatusForbidden, wantCalled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := called
			req := httptest.NewRequest(http.MethodPost, "http://"+tt.host+"/api/v1/user/package", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, res.Code)
			}
			if got := res.Header().Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Fatalf("expected allow origin %q, got %q", tt.wantOrigin, got)
			}
			wasCalled := called > before
			if wasCalled != tt.wantCalled {
				t.Fatalf("expected downstream called=%v, got %v", tt.wantCalled, wasCalled)
			}
		})
	}
}

func TestCORSPreflightUsesRestrictedHeadersAndMethods(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	handler := CORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("preflight must not reach downstream handler")
	}))
	req := httptest.NewRequest(http.MethodOptions, "https://panel.example.com/api/v1/user/package", nil)
	req.Host = "panel.example.com"
	req.Header.Set("Origin", "https://panel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, res.Code)
	}
	if got := res.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type, X-Requested-With" {
		t.Fatalf("unexpected allow headers: %q", got)
	}
	if got := res.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Fatalf("unexpected allow methods: %q", got)
	}
}
