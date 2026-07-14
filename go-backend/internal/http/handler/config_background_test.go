package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"go-backend/internal/auth"
	"go-backend/internal/http/middleware"
	"go-backend/internal/http/response"
	"go-backend/internal/store/repo"
)

func TestConfigBackgroundReadUsesSessionCookieWhenAuthMiddlewareIsSkipped(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	const secret = "test-jwt-secret"
	h := New(r, secret, "3.0.16")
	now := time.Now().UnixMilli()
	if err := r.UpsertConfig(configKeyGlobalAppBackground, "global-bg", now); err != nil {
		t.Fatalf("upsert global background: %v", err)
	}
	if err := r.UpsertUserSetting(7, configKeyAppBackground, "personal-bg", now); err != nil {
		t.Fatalf("upsert user background: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/get", bytes.NewBufferString(`{"name":"app_bg_image"}`))
	token, err := auth.GenerateToken(7, "admin", 0, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: token})
	res := httptest.NewRecorder()
	h.getConfigByName(res, req)

	payload := decodeConfigBackgroundResponse(t, res)
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected data type: %T", payload.Data)
	}
	if got := data["value"]; got != "personal-bg" {
		t.Fatalf("expected personal background, got %#v", got)
	}

	listReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/list", nil)
	listReq.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: token})
	listRes := httptest.NewRecorder()
	h.getConfigs(listRes, listReq)
	listPayload := decodeConfigBackgroundResponse(t, listRes)
	cfgMap, ok := listPayload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected list data type: %T", listPayload.Data)
	}
	if got := cfgMap[configKeyAppBackground]; got != "personal-bg" {
		t.Fatalf("expected personal background in list, got %#v", got)
	}
}

func TestConfigBackgroundReadFallsBackToGlobalForGuest(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	h := New(r, "test-jwt-secret", "3.0.16")
	if err := r.UpsertConfig(configKeyGlobalAppBackground, "global-bg", time.Now().UnixMilli()); err != nil {
		t.Fatalf("upsert global background: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/get", bytes.NewBufferString(`{"name":"app_bg_image"}`))
	res := httptest.NewRecorder()
	h.getConfigByName(res, req)

	payload := decodeConfigBackgroundResponse(t, res)
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected data type: %T", payload.Data)
	}
	if got := data["value"]; got != "global-bg" {
		t.Fatalf("expected global background, got %#v", got)
	}
}

func TestPublicConfigEndpointsFilterInternalAndSensitiveValues(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	const secret = "test-jwt-secret"
	h := New(r, secret, "3.0.27")
	now := time.Now().UnixMilli()
	for key, value := range map[string]string{
		"app_name":                "FLVXR2",
		"registration_enabled":    "false",
		"forward_group_order_map": `{"1":2}`,
		"license_key":             "license-secret",
		"hmac_key":                "hmac-secret",
		"cloudflare_secret_key":   "captcha-secret",
	} {
		if err := r.UpsertConfig(key, value, now); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}

	guestReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/list", nil)
	guestRes := httptest.NewRecorder()
	h.getConfigs(guestRes, guestReq)
	guestPayload := decodeConfigBackgroundResponse(t, guestRes)
	guestConfigs := guestPayload.Data.(map[string]interface{})
	if guestConfigs["app_name"] != "FLVXR2" {
		t.Fatalf("expected public app_name, got %#v", guestConfigs["app_name"])
	}
	for _, key := range []string{"forward_group_order_map", "license_key", "hmac_key", "cloudflare_secret_key"} {
		if _, ok := guestConfigs[key]; ok {
			t.Fatalf("guest config response exposed %s", key)
		}
	}

	adminToken, err := auth.GenerateToken(1, "admin", 0, secret)
	if err != nil {
		t.Fatalf("generate admin token: %v", err)
	}
	adminReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/list", nil)
	adminReq.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: adminToken})
	adminRes := httptest.NewRecorder()
	h.getConfigs(adminRes, adminReq)
	adminPayload := decodeConfigBackgroundResponse(t, adminRes)
	adminConfigs := adminPayload.Data.(map[string]interface{})
	if _, ok := adminConfigs["forward_group_order_map"]; !ok {
		t.Fatal("admin response must retain non-sensitive internal config")
	}
	for _, key := range []string{"license_key", "hmac_key", "cloudflare_secret_key"} {
		if _, ok := adminConfigs[key]; ok {
			t.Fatalf("admin config list exposed write-only secret %s", key)
		}
	}
}

func TestConfigGetRejectsInternalKeysForNonAdmin(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	const secret = "test-jwt-secret"
	h := New(r, secret, "3.0.27")
	if err := r.UpsertConfig("forward_group_order_map", `{"1":2}`, time.Now().UnixMilli()); err != nil {
		t.Fatalf("upsert internal config: %v", err)
	}

	userToken, err := auth.GenerateToken(2, "user", 1, secret)
	if err != nil {
		t.Fatalf("generate user token: %v", err)
	}
	userReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/get", bytes.NewBufferString(`{"name":"forward_group_order_map"}`))
	userReq.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: userToken})
	userRes := httptest.NewRecorder()
	h.getConfigByName(userRes, userReq)
	var userPayload response.R
	if err := json.Unmarshal(userRes.Body.Bytes(), &userPayload); err != nil {
		t.Fatalf("decode user response: %v", err)
	}
	if userPayload.Code != 403 {
		t.Fatalf("expected code 403, got %d", userPayload.Code)
	}

	adminToken, err := auth.GenerateToken(1, "admin", 0, secret)
	if err != nil {
		t.Fatalf("generate admin token: %v", err)
	}
	adminReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/get", bytes.NewBufferString(`{"name":"forward_group_order_map"}`))
	adminReq.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: adminToken})
	adminRes := httptest.NewRecorder()
	h.getConfigByName(adminRes, adminReq)
	decodeConfigBackgroundResponse(t, adminRes)
}

func decodeConfigBackgroundResponse(t *testing.T, res *httptest.ResponseRecorder) response.R {
	t.Helper()
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", res.Code, res.Body.String())
	}
	var payload response.R
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, res.Body.String())
	}
	if payload.Code != 0 {
		t.Fatalf("unexpected response code: %d msg=%s", payload.Code, payload.Msg)
	}
	return payload
}
