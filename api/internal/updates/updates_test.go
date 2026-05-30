package updates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFrequency_IsValid(t *testing.T) {
	cases := map[Frequency]bool{
		FrequencyOff:     true,
		FrequencyDaily:   true,
		FrequencyWeekly:  true,
		FrequencyMonthly: true,
		Frequency(""):    false,
		Frequency("yes"): false,
	}
	for f, want := range cases {
		if got := f.IsValid(); got != want {
			t.Errorf("IsValid(%q) = %v, want %v", f, got, want)
		}
	}
}

func TestFrequency_Interval(t *testing.T) {
	cases := map[Frequency]time.Duration{
		FrequencyOff:          0,
		FrequencyDaily:        24 * time.Hour,
		FrequencyWeekly:       7 * 24 * time.Hour,
		FrequencyMonthly:      30 * 24 * time.Hour,
		Frequency("nonsense"): 0,
	}
	for f, want := range cases {
		if got := f.Interval(); got != want {
			t.Errorf("Interval(%q) = %v, want %v", f, got, want)
		}
	}
}

func TestUpdateAvailable(t *testing.T) {
	ptr := func(s string) *string { return &s }
	cases := []struct {
		name    string
		current string
		latest  *string
		want    bool
	}{
		{"dev build, never alerts", "dev", ptr("v0.5.0"), false},
		{"empty current, never alerts", "", ptr("v0.5.0"), false},
		{"no latest cached", "v0.5.0", nil, false},
		{"empty latest string", "v0.5.0", ptr(""), false},
		{"matching versions", "v0.5.0", ptr("v0.5.0"), false},
		{"newer available", "v0.5.0", ptr("v0.5.1"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := updateAvailable(tc.current, tc.latest); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFetchLatestRelease_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"tag_name": "v0.5.1",
			"html_url": "https://github.com/ponack/touchstone-grc/releases/tag/v0.5.1",
			"published_at": "2026-05-30T12:00:00Z",
			"draft": false,
			"prerelease": false
		}`))
	}))
	defer srv.Close()

	tag, url, publishedAt, ok, err := fetchLatestRelease(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchLatestRelease: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true on 200")
	}
	if tag != "v0.5.1" {
		t.Errorf("tag = %q", tag)
	}
	if url == "" {
		t.Error("url not set")
	}
	if publishedAt == nil || publishedAt.Year() != 2026 {
		t.Errorf("publishedAt = %v", publishedAt)
	}
}

func TestFetchLatestRelease_NotFound(t *testing.T) {
	// Repo with no releases yet returns 404 — the poller treats this
	// as a successful "no release" check rather than an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tag, _, _, ok, err := fetchLatestRelease(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("expected nil err on 404, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false on 404")
	}
	if tag != "" {
		t.Errorf("tag should be empty on 404, got %q", tag)
	}
}

func TestFetchLatestRelease_RejectsDraftOrPrerelease(t *testing.T) {
	cases := map[string]string{
		"draft":      `{"tag_name":"v0.5.1","draft":true}`,
		"prerelease": `{"tag_name":"v0.5.1-rc1","prerelease":true}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			if _, _, _, _, err := fetchLatestRelease(context.Background(), srv.Client(), srv.URL); err == nil {
				t.Fatal("expected error for draft/prerelease, got nil")
			}
		})
	}
}

func TestFetchLatestRelease_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal blah"))
	}))
	defer srv.Close()

	if _, _, _, _, err := fetchLatestRelease(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}
