package auth

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const (
	ContextUserID  = "userID"
	ContextOrgID   = "orgID"
	ContextEmail   = "email"
	ContextName    = "name"
	ContextOrgRole = "orgRole"
)

// RequireUser is Echo middleware that rejects requests without a valid
// session cookie. On success, the user's claims are pushed into the
// echo context for downstream handlers.
func RequireUser(secret string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "no session")
			}
			claims, err := VerifySession(secret, cookie.Value)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid session")
			}
			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
			}
			c.Set(ContextUserID, userID)
			c.Set(ContextOrgID, claims.OrgID)
			c.Set(ContextEmail, claims.Email)
			c.Set(ContextName, claims.Name)
			return next(c)
		}
	}
}

// RequireAdmin must run *after* RequireUser. It looks up the
// users.is_admin column for the session's user id and rejects with
// 403 when the flag is false. This is the platform super-admin flag
// — distinct from per-org "admin" roles in organization_members.
//
// System-wide settings (update-check cadence, install-time config)
// live behind this middleware; per-org settings use RequireOrgRole.
func RequireAdmin(pool *pgxpool.Pool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, ok := c.Get(ContextUserID).(uuid.UUID)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "no session")
			}
			var isAdmin bool
			err := pool.QueryRow(c.Request().Context(),
				`SELECT is_admin FROM users WHERE id = $1`, userID).Scan(&isAdmin)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "admin lookup failed")
			}
			if !isAdmin {
				return echo.NewHTTPError(http.StatusForbidden, "admin role required")
			}
			return next(c)
		}
	}
}

// RequireOrgRole must run *after* RequireUser. It checks the
// session user's role in the session's org against the allowed
// set. The standard idiom for GRC mutating endpoints is
// RequireOrgRole(pool, "admin", "member") — auditor sees the
// list but cannot create / update / delete rows.
//
// A nil/empty allowed set is treated as "any org member" which
// is equivalent to membership-only access checks.
func RequireOrgRole(pool *pgxpool.Pool, allowed ...string) echo.MiddlewareFunc {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		allowSet[r] = struct{}{}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, ok := c.Get(ContextUserID).(uuid.UUID)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "no session")
			}
			orgID, ok := c.Get(ContextOrgID).(uuid.UUID)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "no org context")
			}
			var role string
			err := pool.QueryRow(c.Request().Context(),
				`SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2`,
				orgID, userID).Scan(&role)
			if err != nil {
				return echo.NewHTTPError(http.StatusForbidden, "not a member of this organization")
			}
			if len(allowSet) > 0 {
				if _, ok := allowSet[role]; !ok {
					return echo.NewHTTPError(http.StatusForbidden, "insufficient org role")
				}
			}
			c.Set(ContextOrgRole, role)
			return next(c)
		}
	}
}
