package updates

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/ponack/touchstone/internal/version"
)

// Handler binds the updates package to its HTTP routes. /version is
// available to every authenticated user; /settings/update-check is
// admin-only and lives behind the RequireAdmin middleware the
// caller installs.
type Handler struct {
	store  *Store
	poller *Poller
}

func NewHandler(store *Store, poller *Poller) *Handler {
	return &Handler{store: store, poller: poller}
}

// RegisterUser mounts the user-facing read-only routes onto the
// supplied group (already gated by RequireUser).
func (h *Handler) RegisterUser(g *echo.Group) {
	g.GET("/version", h.getVersion)
}

// RegisterAdmin mounts the admin-only mutation routes onto the
// supplied group (already gated by RequireAdmin).
func (h *Handler) RegisterAdmin(g *echo.Group) {
	g.GET("/settings/update-check", h.getUpdateCheck)
	g.PUT("/settings/update-check", h.putUpdateCheck)
	g.POST("/settings/update-check/run", h.runUpdateCheck)
}

type versionResponse struct {
	Current              string     `json:"current"`
	Latest               *string    `json:"latest"`
	LatestURL            *string    `json:"latest_url"`
	LatestPublishedAt    *time.Time `json:"latest_published_at"`
	LastCheckedAt        *time.Time `json:"last_checked_at"`
	UpdateAvailable      bool       `json:"update_available"`
	UpdateCheckFrequency Frequency  `json:"update_check_frequency"`
}

func (h *Handler) getVersion(c echo.Context) error {
	s, err := h.store.Load(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	resp := versionResponse{
		Current:              version.Build,
		Latest:               s.LatestReleaseTag,
		LatestURL:            s.LatestReleaseURL,
		LatestPublishedAt:    s.LatestReleasePublishedAt,
		LastCheckedAt:        s.LastCheckedAt,
		UpdateAvailable:      updateAvailable(version.Build, s.LatestReleaseTag),
		UpdateCheckFrequency: s.Frequency,
	}
	return c.JSON(http.StatusOK, resp)
}

type updateCheckResponse struct {
	Frequency     Frequency  `json:"frequency"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
}

func (h *Handler) getUpdateCheck(c echo.Context) error {
	s, err := h.store.Load(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, updateCheckResponse{
		Frequency:     s.Frequency,
		LastCheckedAt: s.LastCheckedAt,
	})
}

type putUpdateCheckRequest struct {
	Frequency Frequency `json:"frequency"`
}

func (h *Handler) putUpdateCheck(c echo.Context) error {
	var req putUpdateCheckRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if !req.Frequency.IsValid() {
		return echo.NewHTTPError(http.StatusBadRequest, "frequency must be one of off, daily, weekly, monthly")
	}
	if err := h.store.SetFrequency(c.Request().Context(), req.Frequency); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return h.getUpdateCheck(c)
}

func (h *Handler) runUpdateCheck(c echo.Context) error {
	if err := h.poller.PollOnce(c.Request().Context()); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, err.Error())
	}
	return h.getUpdateCheck(c)
}

// updateAvailable returns true when the latest known tag is newer
// than the running build. Both are compared as plain strings — the
// release process always emits semver tags ("v0.5.1") so lexical
// comparison Just Works for the single-digit majors we ship today.
// When current is "dev" or empty, no update notice is shown
// (operator is running an unreleased build).
func updateAvailable(current string, latest *string) bool {
	if latest == nil || *latest == "" {
		return false
	}
	if current == "" || current == "dev" {
		return false
	}
	return *latest != current
}
