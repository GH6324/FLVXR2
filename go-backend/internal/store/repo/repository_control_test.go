package repo

import (
	"path/filepath"
	"testing"
	"time"

	"go-backend/internal/store/model"
)

func TestListActiveNftablesForwardsUsesForwardTable(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	now := time.Now().UnixMilli()
	items := []model.Forward{
		{UserID: 1, UserName: "admin", Name: "active nft", TunnelID: 10, RemoteAddr: "example.com:443", Strategy: "fifo", Status: 1, Mode: "nftables", CreatedTime: now, UpdatedTime: now},
		{UserID: 1, UserName: "admin", Name: "inactive nft", TunnelID: 11, RemoteAddr: "example.net:443", Strategy: "fifo", Status: 0, Mode: "nftables", CreatedTime: now, UpdatedTime: now},
		{UserID: 1, UserName: "admin", Name: "active gost", TunnelID: 12, RemoteAddr: "example.org:443", Strategy: "fifo", Status: 1, Mode: "gost", CreatedTime: now, UpdatedTime: now},
	}
	for i := range items {
		if err := r.DB().Create(&items[i]).Error; err != nil {
			t.Fatalf("create forward %d: %v", i, err)
		}
	}

	forwards, err := r.ListActiveNftablesForwards()
	if err != nil {
		t.Fatalf("list active nftables forwards: %v", err)
	}
	if len(forwards) != 1 {
		t.Fatalf("expected one active nftables forward, got %d", len(forwards))
	}
	if forwards[0].Name != "active nft" || forwards[0].RemoteAddr != "example.com:443" || forwards[0].TunnelID != 10 {
		t.Fatalf("unexpected forward: %#v", forwards[0])
	}
}
