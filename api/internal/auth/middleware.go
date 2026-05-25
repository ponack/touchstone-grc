package auth

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const (
	ContextUserID = "userID"
	ContextOrgID  = "orgID"
	ContextEmail  = "email"
	ContextName   = "name"
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
