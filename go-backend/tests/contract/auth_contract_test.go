package contract_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-backend/internal/auth"
	"go-backend/internal/http/middleware"
	"go-backend/internal/http/response"
)

func TestJWTMiddlewareContracts(t *testing.T) {
	secret := "unit-test-secret"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.WriteJSON(w, response.OK("pass"))
	})

	wrapped := middleware.JWT(middleware.AuthOptions{JWTSecret: secret})(next)

	t.Run("login path is excluded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/user/login", nil)
		res := httptest.NewRecorder()
		wrapped.ServeHTTP(res, req)
		assertCode(t, res, 0)
	})

	t.Run("missing token returns 401 contract message", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnel/list", nil)
		res := httptest.NewRecorder()
		wrapped.ServeHTTP(res, req)
		assertCodeMsg(t, res, 401, "未登录或token已过期")
	})

	t.Run("invalid token returns 401 contract message", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnel/list", nil)
		req.Header.Set("Authorization", "invalid.token.value")
		res := httptest.NewRecorder()
		wrapped.ServeHTTP(res, req)
		assertCodeMsg(t, res, 401, "无效的token或token已过期")
	})

	t.Run("valid token reaches next", func(t *testing.T) {
		token, err := auth.GenerateToken(1, "admin_user", 0, secret)
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnel/list", nil)
		req.Header.Set("Authorization", token)
		res := httptest.NewRecorder()
		wrapped.ServeHTTP(res, req)
		assertCode(t, res, 0)
	})

	t.Run("non-admin blocked on admin path", func(t *testing.T) {
		token, err := auth.GenerateToken(2, "normal_user", 1, secret)
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/update", nil)
		req.Header.Set("Authorization", token)
		res := httptest.NewRecorder()
		wrapped.ServeHTTP(res, req)
		assertCodeMsg(t, res, 403, "权限不足，仅管理员可操作")
	})

	t.Run("non-admin blocked on every sensitive route family", func(t *testing.T) {
		token, err := auth.GenerateToken(2, "normal_user", 1, secret)
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		paths := []string{
			"/api/v1/system/upgrade",
			"/api/v1/panel/upgrade",
			"/api/v1/license/config",
			"/api/v1/license/transfer",
			"/api/v1/node-group/create",
			"/api/v1/node-tag/create",
			"/api/v1/policy/bundle",
			"/api/v1/payment/stats",
			"/api/v1/payment/config/admin/list",
			"/api/v1/billing/redeem/list",
			"/api/v1/billing/balance-log/list",
			"/api/v1/user/batch-delete",
			"/api/v1/user/quota/reset",
			"/api/v1/tunnel-group/create",
		}
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", token)
			res := httptest.NewRecorder()
			wrapped.ServeHTTP(res, req)
			assertCodeMsg(t, res, 403, "权限不足，仅管理员可操作")
		}
	})

	t.Run("non-admin can reach authenticated self-service routes", func(t *testing.T) {
		token, err := auth.GenerateToken(2, "normal_user", 1, secret)
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		paths := []string{
			"/api/v1/user/package",
			"/api/v1/payment/config",
			"/api/v1/billing/feature-status",
			"/api/v1/tunnel/user/tunnel",
		}
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", token)
			res := httptest.NewRecorder()
			wrapped.ServeHTTP(res, req)
			assertCode(t, res, 0)
		}
	})

	t.Run("signed payment callbacks bypass JWT", func(t *testing.T) {
		for _, path := range []string{
			"/api/v1/payment/callback/yipay",
			"/api/v1/payment/callback/usdt",
		} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			res := httptest.NewRecorder()
			wrapped.ServeHTTP(res, req)
			assertCode(t, res, 0)
		}
	})
}

func assertCode(t *testing.T, rec *httptest.ResponseRecorder, expected int) {
	t.Helper()
	var out response.R
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Code != expected {
		t.Fatalf("expected code %d, got %d", expected, out.Code)
	}
}

func assertCodeMsg(t *testing.T, rec *httptest.ResponseRecorder, expectedCode int, expectedMsg string) {
	t.Helper()
	var out response.R
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Code != expectedCode || out.Msg != expectedMsg {
		t.Fatalf("expected (%d,%q), got (%d,%q)", expectedCode, expectedMsg, out.Code, out.Msg)
	}
}
