package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	SessionCookieName = "touchstone_session"
	sessionTTL        = 24 * time.Hour
)

type SessionClaims struct {
	OrgID uuid.UUID `json:"org_id"`
	Email string    `json:"email"`
	Name  string    `json:"name"`
	jwt.RegisteredClaims
}

func SignSession(secret string, userID, orgID uuid.UUID, email, name string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(sessionTTL)
	claims := SessionClaims{
		OrgID: orgID,
		Email: email,
		Name:  name,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    "touchstone",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign session: %w", err)
	}
	return signed, exp, nil
}

func VerifySession(secret, raw string) (*SessionClaims, error) {
	var claims SessionClaims
	tok, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid session")
	}
	return &claims, nil
}
