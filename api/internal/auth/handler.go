package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

	"github.com/ponack/touchstone/internal/audit"
	"github.com/ponack/touchstone/internal/config"
)

type Handler struct {
	cfg      *config.Config
	pool     *pgxpool.Pool
	provider *gooidc.Provider
	oauth2   *oauth2.Config
}

func NewHandler(cfg *config.Config, pool *pgxpool.Pool) (*Handler, error) {
	h := &Handler{cfg: cfg, pool: pool}

	if cfg.OIDC.IssuerURL != "" {
		if cfg.OIDC.ClientID == "" || cfg.OIDC.ClientSecret == "" || cfg.OIDC.RedirectURL == "" {
			return nil, fmt.Errorf("OIDC_ISSUER_URL is set but OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_REDIRECT_URL are missing")
		}
		provider, err := gooidc.NewProvider(context.Background(), cfg.OIDC.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("initialise OIDC provider %q: %w", cfg.OIDC.IssuerURL, err)
		}
		h.provider = provider
		h.oauth2 = &oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
		}
		slog.Info("OIDC configured", "issuer", cfg.OIDC.IssuerURL)
	}

	return h, nil
}

// Register wires the auth routes onto the Echo group. OIDC routes are
// registered only when the provider has been configured.
func (h *Handler) Register(e *echo.Echo) {
	e.GET("/auth/config", h.GetAuthConfig)
	e.POST("/auth/login", h.LocalLogin)
	e.POST("/auth/logout", h.Logout)

	if h.provider != nil {
		e.GET("/auth/oidc/start", h.OIDCStart)
		e.GET("/auth/oidc/callback", h.OIDCCallback)
	}
}

// GetAuthConfig advertises which authentication methods are available.
func (h *Handler) GetAuthConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{
		"oidc":  h.provider != nil,
		"local": h.cfg.Local.Enabled,
	})
}

// LocalLogin authenticates a user against the local-auth env vars and
// returns a session cookie. Idempotent: on first successful login the
// user + default org are provisioned.
func (h *Handler) LocalLogin(c echo.Context) error {
	if !h.cfg.Local.Enabled {
		return echo.NewHTTPError(http.StatusNotFound, "local auth not enabled")
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	if req.Email != h.cfg.Local.Email || req.Password != h.cfg.Local.Password {
		ctxJSON, _ := json.Marshal(map[string]string{"email": req.Email, "method": "local"})
		audit.Record(c.Request().Context(), h.pool, audit.Event{
			Action:    "auth.login.failed",
			IPAddress: c.RealIP(),
			Context:   ctxJSON,
		})
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	userID, orgID, err := h.upsertLocalAdmin(c.Request().Context(), req.Email)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to provision user")
	}

	if err := h.issueSession(c, userID, orgID, req.Email, req.Email); err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]string{"email": req.Email, "method": "local"})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:   &userID,
		Action:    "auth.login.success",
		OrgID:     &orgID,
		IPAddress: c.RealIP(),
		Context:   ctxJSON,
	})

	return c.JSON(http.StatusOK, map[string]any{
		"user_id": userID,
		"org_id":  orgID,
		"email":   req.Email,
	})
}

// Logout clears the session cookie.
func (h *Handler) Logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Env == "production",
		SameSite: http.SameSiteLaxMode,
	})
	return c.NoContent(http.StatusNoContent)
}

// issueSession signs a session JWT and sets the HttpOnly cookie. Shared
// by the local-auth and OIDC paths so the session shape stays identical
// regardless of which method authenticated the user.
func (h *Handler) issueSession(c echo.Context, userID, orgID uuid.UUID, email, name string) error {
	token, exp, err := SignSession(h.cfg.SecretKey, userID, orgID, email, name)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to mint session")
	}
	c.SetCookie(&http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   h.cfg.Env == "production",
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// upsertLocalAdmin returns (userID, orgID) for the local-auth admin. On
// first call it creates the user, a default organization, and the admin
// membership in a single transaction.
func (h *Handler) upsertLocalAdmin(ctx context.Context, email string) (uuid.UUID, uuid.UUID, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			INSERT INTO users (email, name, is_admin)
			VALUES ($1, $1, true)
			RETURNING id
		`, email).Scan(&userID)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	var orgID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = 'default'`).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			INSERT INTO organizations (slug, name)
			VALUES ('default', 'Default')
			RETURNING id
		`).Scan(&orgID)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO organization_members (org_id, user_id, role)
		VALUES ($1, $2, 'admin')
		ON CONFLICT (org_id, user_id) DO NOTHING
	`, orgID, userID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, orgID, nil
}
