package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-backend/internal/security"
	"go-backend/internal/store/repo"
)

func TestLoginMigratesLegacyMD5Password(t *testing.T) {
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	now := time.Now().UnixMilli()
	userID, err := r.CreateUser("legacy-user", security.MD5("legacy-password"), 1, now+86400000, 10, 1, 1, 0, 1, now, 0, 0, 0, nil)
	if err != nil {
		t.Fatalf("create legacy user: %v", err)
	}

	h := New(r, "test-jwt-secret", "3.0.27")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user/login", bytes.NewBufferString(`{"username":"legacy-user","password":"legacy-password"}`))
	res := httptest.NewRecorder()
	h.login(res, req)
	decodeConfigBackgroundResponse(t, res)

	user, err := r.GetUserByID(userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user == nil || !strings.HasPrefix(user.Pwd, "$2") {
		t.Fatalf("expected bcrypt password after login, got %#v", user)
	}
	valid, needsUpgrade := security.VerifyPassword(user.Pwd, "legacy-password")
	if !valid || needsUpgrade {
		t.Fatalf("migrated password verification failed: valid=%v upgrade=%v", valid, needsUpgrade)
	}
}
