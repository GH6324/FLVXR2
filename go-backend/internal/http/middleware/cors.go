package middleware

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

func CORS(next http.Handler) http.Handler {
	allowedOrigins := configuredAllowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !isAllowedOrigin(r, origin, allowedOrigins) {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Expose-Headers", "Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func configuredAllowedOrigins() map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, value := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		origin := strings.TrimSpace(value)
		if origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return allowed
}

func isAllowedOrigin(r *http.Request, origin string, allowed map[string]struct{}) bool {
	if _, ok := allowed[origin]; ok {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return false
	}
	return strings.EqualFold(parsed.Scheme, requestScheme(r))
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if strings.EqualFold(forwarded, "https") {
		return "https"
	}
	return "http"
}
