package handler

import (
	"encoding/json"
	"testing"
)

func TestPublicPaymentConfigDoesNotExposeSecrets(t *testing.T) {
	raw := `{"network":"tron","token":"usdt","pid":"merchant-id","secret_key":"top-secret","api_url":"https://pay.example.com"}`
	got := publicPaymentConfig("USDT", raw)
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(got), &config); err != nil {
		t.Fatalf("decode public config: %v", err)
	}
	if config["network"] != "tron" {
		t.Fatalf("expected network metadata, got %#v", config["network"])
	}
	for _, key := range []string{"token", "pid", "secret_key", "api_url"} {
		if _, ok := config[key]; ok {
			t.Fatalf("public payment config exposed %s", key)
		}
	}
}

func TestPublicPaymentConfigForYipayIsEmpty(t *testing.T) {
	got := publicPaymentConfig("YIPAY", `{"pid":"merchant-id","secret_key":"top-secret"}`)
	if got != "{}" {
		t.Fatalf("expected empty public YIPAY config, got %s", got)
	}
}
