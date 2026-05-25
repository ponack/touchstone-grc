package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

	"github.com/ponack/touchstone/internal/audit"
)

const (
	oauthStateCookie = "oauth_state"
	oauthPKCECookie  = "oauth_pkce"
	oauthCookieTTL   = 300 // 5 minutes
)

// OIDCStart begins the OIDC PKCE flow: mints state + PKCE verifier into
// short-lived HttpOnly cookies and redirects the browser to the IdP.
func (h *Handler) OIDCStart(c echo.Context) error {
	if h.provider == nil {
		return echo.NewHTTPError(http.StatusNotFound, "OIDC not configured")
	}

	state, err := randomString(16)
	if err != nil {
		return err
	}
	nonce, err := randomString(16)
	if err != nil {
		return err
	}
	pkceVerifier, err := randomString(32)
	if err != nil {
		return err
	}

	secure := h.cfg.Env == "production"
	c.SetCookie(&http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   oauthCookieTTL,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     oauthPKCECookie,
		Value:    pkceVerifier,
		Path:     "/",
		MaxAge:   oauthCookieTTL,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.oauth2.AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

// OIDCCallback handles the IdP redirect: validates state + PKCE, exchanges
// the code, verifies the ID token, upserts the user, mints the session
// cookie, and redirects back to the UI.
func (h *Handler) OIDCCallback(c echo.Context) error {
	if h.provider == nil {
		return echo.NewHTTPError(http.StatusNotFound, "OIDC not configured")
	}

	stateCookie, err := c.Cookie(oauthStateCookie)
	if err != nil || stateCookie.Value != c.QueryParam("state") {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid oauth state")
	}
	c.SetCookie(&http.Cookie{Name: oauthStateCookie, MaxAge: -1, Path: "/"})

	pkceCookie, err := c.Cookie(oauthPKCECookie)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "missing pkce cookie")
	}
	c.SetCookie(&http.Cookie{Name: oauthPKCECookie, MaxAge: -1, Path: "/"})

	code := c.QueryParam("code")
	if code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing code")
	}

	token, err := h.oauth2.Exchange(
		c.Request().Context(),
		code,
		oauth2.VerifierOption(pkceCookie.Value),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "token exchange failed")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing id_token")
	}

	verifier := h.provider.Verifier(&gooidc.Config{ClientID: h.cfg.OIDC.ClientID})
	idToken, err := verifier.Verify(c.Request().Context(), rawIDToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid id_token")
	}

	var idClaims struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := idToken.Claims(&idClaims); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to parse claims")
	}
	if idClaims.Email == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "id_token missing email claim")
	}
	if idClaims.Name == "" {
		idClaims.Name = idClaims.Email
	}

	userID, orgID, err := h.upsertOIDCUser(c.Request().Context(), idClaims.Email, idClaims.Name, idClaims.Picture)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to provision user")
	}

	if err := h.issueSession(c, userID, orgID, idClaims.Email, idClaims.Name); err != nil {
		return err
	}

	ctxJSON, _ := json.Marshal(map[string]string{"email": idClaims.Email, "method": "oidc"})
	audit.Record(c.Request().Context(), h.pool, audit.Event{
		ActorID:   &userID,
		Action:    "auth.login.success",
		OrgID:     &orgID,
		IPAddress: c.RealIP(),
		Context:   ctxJSON,
	})

	dest := h.cfg.BaseURL
	if dest == "" {
		dest = "/"
	}
	return c.Redirect(http.StatusTemporaryRedirect, dest)
}

// upsertOIDCUser creates or updates the user from IdP claims and ensures
// they are a member of the default org. New OIDC users land as 'member',
// not 'admin' — the local-auth bootstrap admin remains the only admin
// until promoted explicitly. If the default org does not yet exist (no
// local-auth login has run), it is created.
func (h *Handler) upsertOIDCUser(ctx context.Context, email, name, avatarURL string) (uuid.UUID, uuid.UUID, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (email, name, avatar_url)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (email) DO UPDATE
		  SET name       = EXCLUDED.name,
		      avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
		      updated_at = now()
		RETURNING id
	`, email, name, avatarURL).Scan(&userID); err != nil {
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

	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_members (org_id, user_id, role)
		VALUES ($1, $2, 'member')
		ON CONFLICT (org_id, user_id) DO NOTHING
	`, orgID, userID); err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, orgID, nil
}

// randomString returns n random bytes, base64url-encoded without padding.
// 32 bytes → 43 chars (meets RFC 7636 minimum for PKCE verifier);
// 16 bytes → 22 chars (state / nonce).
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
