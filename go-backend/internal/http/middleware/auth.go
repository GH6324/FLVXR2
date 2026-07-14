package middleware

import (
	"context"
	"net/http"
	"strings"

	"go-backend/internal/auth"
	"go-backend/internal/http/response"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"
const SessionCookieName = "flvx_session"

type AuthOptions struct {
	JWTSecret string
}

func JWT(opts AuthOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if shouldSkip(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			token := bearerToken(strings.TrimSpace(r.Header.Get("Authorization")))
			if token == "" {
				if cookie, err := r.Cookie(SessionCookieName); err == nil {
					token = strings.TrimSpace(cookie.Value)
				}
			}
			if token == "" {
				response.WriteJSON(w, response.Err(401, "未登录或token已过期"))
				return
			}

			claims, ok := auth.ValidateToken(token, opts.JWTSecret)
			if !ok {
				response.WriteJSON(w, response.Err(401, "无效的token或token已过期"))
				return
			}

			if requiresAdmin(r.URL.Path) && claims.RoleID != 0 {
				response.WriteJSON(w, response.Err(403, "权限不足，仅管理员可操作"))
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(value string) string {
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return value
}

func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Context().Value(ClaimsContextKey)
		claims, ok := raw.(auth.Claims)
		if !ok {
			response.WriteJSON(w, response.Err(401, "无法获取用户权限信息"))
			return
		}
		if claims.RoleID != 0 {
			response.WriteJSON(w, response.Err(403, "权限不足，仅管理员可操作"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func shouldSkip(path string) bool {
	switch {
	case strings.HasPrefix(path, "/flow/"):
		return true
	case path == "/api/v1/monitor/public/nodes":
		return true
	case path == "/api/v1/monitor/public/nodes/metrics":
		return true
	case strings.HasPrefix(path, "/api/v1/open_api/"):
		return true
	case strings.HasPrefix(path, "/api/v1/captcha/"):
		return true
	case path == "/api/v1/config/get":
		return true
	case path == "/api/v1/config/list":
		return true
	case path == "/api/v1/user/login":
		return true
	case path == "/api/v1/user/logout":
		return true
	case path == "/api/v1/user/register":
		return true
	case path == "/api/v1/payment/callback/yipay":
		return true
	case path == "/api/v1/payment/callback/usdt":
		return true
	case path == "/api/v1/node/info":
		return true
	case path == "/api/v1/federation/connect":
		return true
	case path == "/api/v1/federation/tunnel/create":
		return true
	case path == "/api/v1/federation/runtime/reserve-port":
		return true
	case path == "/api/v1/federation/runtime/apply-role":
		return true
	case path == "/api/v1/federation/runtime/release-role":
		return true
	case path == "/api/v1/federation/runtime/diagnose":
		return true
	case path == "/api/v1/federation/runtime/command":
		return true
	default:
		return false
	}
}

func requiresAdmin(path string) bool {
	if path == "/api/v1/tunnel/user/tunnel" {
		return false
	}

	for _, prefix := range adminPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	_, ok := adminPaths[path]
	return ok
}

var adminPathPrefixes = []string{
	"/api/v1/monitor/permission/",
	"/api/v1/group/",
	"/api/v1/federation/share/",
	"/api/v1/federation/node/",
	"/api/v1/node/",
	"/api/v1/node-group/",
	"/api/v1/node-tag/",
	"/api/v1/tls-template/",
	"/api/v1/path/",
	"/api/v1/speed-limit/",
	"/api/v1/policy/",
	"/api/v1/backup/",
	"/api/v1/api/v1/backup/",
	"/api/v1/tunnel/",
	"/api/v1/tunnel-group-new/",
	"/api/v1/tunnel-group/",
	"/api/v1/tunnel-list/",
	"/api/v1/order/admin/",
}

var adminPaths = map[string]struct{}{
	"/api/v1/user/create":                     {},
	"/api/v1/user/list":                       {},
	"/api/v1/user/update":                     {},
	"/api/v1/user/delete":                     {},
	"/api/v1/user/batch-delete":               {},
	"/api/v1/user/reset":                      {},
	"/api/v1/user/batch-reset":                {},
	"/api/v1/user/quota/reset":                {},
	"/api/v1/user/quota/history":              {},
	"/api/v1/user/quota/history/delete":       {},
	"/api/v1/user/renewal-logs":               {},
	"/api/v1/user/renewal-log/delete":         {},
	"/api/v1/user/update-order":               {},
	"/api/v1/user/groups":                     {},
	"/api/v1/config/update":                   {},
	"/api/v1/config/update-single":            {},
	"/api/v1/announcement/update":             {},
	"/api/v1/system/upgrade":                  {},
	"/api/v1/panel/upgrade/check":             {},
	"/api/v1/panel/upgrade/releases":          {},
	"/api/v1/panel/upgrade":                   {},
	"/api/v1/license/config":                  {},
	"/api/v1/license/transfer":                {},
	"/api/v1/payment/stats":                   {},
	"/api/v1/payment/config/save":             {},
	"/api/v1/payment/config/admin/list":       {},
	"/api/v1/payment/config/delete":           {},
	"/api/v1/billing/redeem/create":           {},
	"/api/v1/billing/redeem/list":             {},
	"/api/v1/billing/redeem/delete":           {},
	"/api/v1/billing/discount/create":         {},
	"/api/v1/billing/discount/list":           {},
	"/api/v1/billing/discount/delete":         {},
	"/api/v1/billing/balance-log/list":        {},
	"/api/v1/billing/balance-log/delete":      {},
	"/api/v1/billing/balance-log/cleanup":     {},
	"/api/v1/billing/feature-status/save":     {},
	"/api/v1/package/create":                  {},
	"/api/v1/package/update":                  {},
	"/api/v1/package/delete":                  {},
	"/api/v1/package/assign":                  {},
	"/api/v1/package/store-status/save":       {},
	"/api/v1/package/toggle-auto-buy-traffic": {},
}
