package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-backend/internal/auth"
	"go-backend/internal/http/middleware"
	"go-backend/internal/http/response"
)

func TestEnsureSelfOrAdmin(t *testing.T) {
	tests := []struct {
		name     string
		claims   auth.Claims
		targetID int64
		allowed  bool
	}{
		{name: "user can update self", claims: auth.Claims{Sub: "2", RoleID: 1}, targetID: 2, allowed: true},
		{name: "user cannot update another user", claims: auth.Claims{Sub: "2", RoleID: 1}, targetID: 3, allowed: false},
		{name: "admin can update another user", claims: auth.Claims{Sub: "1", RoleID: 0}, targetID: 3, allowed: true},
	}

	h := &Handler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/user/toggle-auto-renew", nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsContextKey, tt.claims))
			res := httptest.NewRecorder()
			if got := h.ensureSelfOrAdmin(res, req, tt.targetID); got != tt.allowed {
				t.Fatalf("expected allowed=%v, got %v", tt.allowed, got)
			}
			if tt.allowed {
				return
			}
			var payload response.R
			if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Code != 403 {
				t.Fatalf("expected code 403, got %d", payload.Code)
			}
		})
	}
}
