package handler

import "testing"

func TestReleasesForChannelIncludesReleaseBody(t *testing.T) {
	releases := []githubRelease{
		{
			TagName:     "3.0.28",
			Name:        "Release 3.0.28",
			Body:        "## Update\n\n- Security fixes",
			PublishedAt: "2026-07-14T00:00:00Z",
		},
		{
			TagName:     "3.0.29-beta.1",
			Name:        "Release 3.0.29-beta.1",
			Body:        "Beta notes",
			PublishedAt: "2026-07-15T00:00:00Z",
			Prerelease:  true,
		},
	}

	items := releasesForChannel(releases, releaseChannelStable)
	if len(items) != 1 {
		t.Fatalf("expected one stable release, got %d", len(items))
	}
	if items[0].Version != "3.0.28" {
		t.Fatalf("expected version 3.0.28, got %q", items[0].Version)
	}
	if items[0].Body != releases[0].Body {
		t.Fatalf("expected release body %q, got %q", releases[0].Body, items[0].Body)
	}
}
