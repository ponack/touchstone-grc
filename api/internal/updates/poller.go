package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// githubReleasesLatestURL points at the public API endpoint that
// returns the most recent non-prerelease release.
const githubReleasesLatestURL = "https://api.github.com/repos/ponack/touchstone-grc/releases/latest"

// Poller runs in a single goroutine and re-checks GitHub releases on
// the operator-configured cadence. It re-reads the cadence on every
// tick so the operator can change it without a process restart.
type Poller struct {
	store      *Store
	client     *http.Client
	endpoint   string
	tickerStep time.Duration // how often to re-read frequency (default 1m)
}

// NewPoller returns a poller wired to the supplied store and the
// default GitHub endpoint. tickerStep controls how responsive the
// poller is to cadence changes — one minute is the right granularity
// for a self-hosted tool.
func NewPoller(store *Store) *Poller {
	return &Poller{
		store:      store,
		client:     &http.Client{Timeout: 15 * time.Second},
		endpoint:   githubReleasesLatestURL,
		tickerStep: 1 * time.Minute,
	}
}

// Run blocks until ctx is cancelled, polling on the cadence the
// store reports. Caller is expected to fire-and-forget Run in a
// goroutine — it returns nil on context cancellation.
func (p *Poller) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.tickerStep)
	defer ticker.Stop()

	// Eager first poll so a freshly-installed instance has cached
	// release data before the first ticker interval elapses.
	p.tryPoll(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.tryPoll(ctx)
		}
	}
}

// tryPoll re-reads the cadence + last-checked-at, decides whether
// it's time to fire a poll, and runs it if so. Errors are logged but
// never break the loop.
func (p *Poller) tryPoll(ctx context.Context) {
	settings, err := p.store.Load(ctx)
	if err != nil {
		slog.Warn("updates: load settings failed", "err", err)
		return
	}
	interval := settings.Frequency.Interval()
	if interval == 0 {
		return // operator has disabled checks
	}
	if settings.LastCheckedAt != nil && time.Since(*settings.LastCheckedAt) < interval {
		return // not yet due
	}
	if err := p.poll(ctx); err != nil {
		slog.Warn("updates: poll failed", "err", err)
	}
}

// PollOnce runs a single poll synchronously, ignoring the cadence.
// Used by the HTTP "check now" endpoint.
func (p *Poller) PollOnce(ctx context.Context) error {
	return p.poll(ctx)
}

type releasePayload struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

func (p *Poller) poll(ctx context.Context) error {
	tag, url, publishedAt, ok, err := fetchLatestRelease(ctx, p.client, p.endpoint)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if !ok {
		// 404 / no release yet — record the check but leave tag/url
		// empty so the UI can show "no release found".
		return p.store.RecordCheck(ctx, "", "", nil, now)
	}
	if err := p.store.RecordCheck(ctx, tag, url, publishedAt, now); err != nil {
		return err
	}
	slog.Info("updates: poll complete", "latest_tag", tag)
	return nil
}

// fetchLatestRelease performs the GitHub HTTP call and decodes the
// response, with no dependency on the Store. ok=false signals a 404
// (repo has no releases yet); errors signal anything unexpected.
// Kept package-local so the test file can exercise it directly via
// httptest.
func fetchLatestRelease(ctx context.Context, client *http.Client, endpoint string) (string, string, *time.Time, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil, false, fmt.Errorf("github releases fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, false, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", "", nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, false, fmt.Errorf("github HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel releasePayload
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", "", nil, false, fmt.Errorf("decode release: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		// /releases/latest never returns drafts/prereleases per docs,
		// but guard anyway in case the endpoint shape changes.
		return "", "", nil, false, errors.New("github returned a draft/prerelease — refusing to cache")
	}

	var publishedAt *time.Time
	if rel.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, rel.PublishedAt); err == nil {
			publishedAt = &t
		}
	}
	return rel.TagName, rel.HTMLURL, publishedAt, true, nil
}
