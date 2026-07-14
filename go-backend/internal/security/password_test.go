package security

import "testing"

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == MD5("correct horse battery staple") {
		t.Fatal("new password hash must not use MD5")
	}
	valid, needsUpgrade := VerifyPassword(hash, "correct horse battery staple")
	if !valid || needsUpgrade {
		t.Fatalf("expected bcrypt password to verify without upgrade, got valid=%v upgrade=%v", valid, needsUpgrade)
	}
	valid, _ = VerifyPassword(hash, "wrong")
	if valid {
		t.Fatal("wrong password must not verify")
	}
}

func TestLegacyMD5PasswordRequestsUpgrade(t *testing.T) {
	valid, needsUpgrade := VerifyPassword(MD5("legacy-password"), "legacy-password")
	if !valid || !needsUpgrade {
		t.Fatalf("expected legacy password to verify and request upgrade, got valid=%v upgrade=%v", valid, needsUpgrade)
	}
	valid, needsUpgrade = VerifyPassword(MD5("legacy-password"), "wrong")
	if valid || needsUpgrade {
		t.Fatalf("wrong legacy password must fail, got valid=%v upgrade=%v", valid, needsUpgrade)
	}
}
