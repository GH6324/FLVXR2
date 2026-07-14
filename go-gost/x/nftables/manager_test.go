package nftables

import (
	"errors"
	"testing"

	"github.com/google/nftables/expr"
)

func TestNewSpeedLimitExpressionUsesMbpsByteRate(t *testing.T) {
	limit := newSpeedLimitExpression(100)
	if limit.Type != expr.LimitTypePktBytes {
		t.Fatalf("expected byte-rate limit, got type %d", limit.Type)
	}
	if limit.Unit != expr.LimitTimeSecond {
		t.Fatalf("expected per-second unit, got %d", limit.Unit)
	}
	if limit.Rate != 12_500_000 {
		t.Fatalf("expected 100 Mbps to equal 12,500,000 bytes/s, got %d", limit.Rate)
	}
}

func TestIsRecoverableOwnedTableDecodeError(t *testing.T) {
	if !isRecoverableOwnedTableDecodeError(errors.New("get rules: expr: invalid limit unit value 0")) {
		t.Fatal("legacy limit-unit corruption should trigger owned-table recovery")
	}
	if !isRecoverableOwnedTableDecodeError(errors.New("expr: invalid limit type 9")) {
		t.Fatal("legacy limit-type corruption should trigger owned-table recovery")
	}
	if isRecoverableOwnedTableDecodeError(errors.New("netlink permission denied")) {
		t.Fatal("unrelated nftables errors must not trigger table recreation")
	}
}
