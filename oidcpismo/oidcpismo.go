// Package oidcpismo provides a library for implementing OIDC client for Pismo.
package oidcpismo

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JwtOptions defines the options for creating a JWT token.
type JwtOptions struct {
	TenantID     string
	UID          string // Pismo account ID
	Pismo        map[string]any
	CustomClaims map[string]any // customClaims are optional

	PrivKey  *rsa.PrivateKey
	Issuer   string
	Subject  string
	Audience string
	Expire   time.Duration // min 1min, max 1h
}

type customClaims struct {
	TenantID     string         `json:"tenant_id"`
	UID          string         `json:"uid"`
	Pismo        map[string]any `json:"pismo"`
	CustomClaims map[string]any `json:"customClaims,omitempty"`

	jwt.RegisteredClaims
}

var (
	// ErrMissingTenantID is missing tenant_id
	ErrMissingTenantID = errors.New("missing tenant_id claim")

	// ErrMissingUID is missing uid
	ErrMissingUID = errors.New("missing uid claim")

	// ErrMissingPismoClaims is missing pismo claims
	ErrMissingPismoClaims = errors.New("missing pismo claims")

	// ErrMissingPrivateKey is missing private key
	ErrMissingPrivateKey = errors.New("missing private key")

	// ErrMissingIssuer is missing issuer
	ErrMissingIssuer = errors.New("missing issuer")

	// ErrMissingSubject is missing subject
	ErrMissingSubject = errors.New("missing subject")

	// ErrMissingAudience is missing audience
	ErrMissingAudience = errors.New("missing audience")
)

// NewJwt creates a new JWT token with the given options.
// See: https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt
func NewJwt(options JwtOptions) (string, error) {

	// Bail out early if required fields are missing
	if options.TenantID == "" {
		return "", ErrMissingTenantID
	}
	if options.UID == "" {
		return "", ErrMissingUID
	}
	if options.Pismo == nil {
		return "", ErrMissingPismoClaims
	}
	if options.PrivKey == nil {
		return "", ErrMissingPrivateKey
	}
	if options.Issuer == "" {
		return "", ErrMissingIssuer
	}
	if options.Subject == "" {
		return "", ErrMissingSubject
	}
	if options.Audience == "" {
		return "", ErrMissingAudience
	}
	if options.Expire < time.Minute || options.Expire > time.Hour {
		return "", fmt.Errorf("invalid expire duration (must be between 1 minute and 1 hour): %v", options.Expire)
	}

	jwt.MarshalSingleStringAsArray = false // This is required because Pismo expects the audience claim to be a single string, not an array of strings.

	now := time.Now()

	claims := customClaims{
		options.TenantID,
		options.UID,
		options.Pismo,
		options.CustomClaims,

		jwt.RegisteredClaims{
			Issuer:    options.Issuer,
			Subject:   options.Subject,
			Audience:  []string{options.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(options.Expire)),
		},
	}

	// generate the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// sign the token using the private key
	ss, err := token.SignedString(options.PrivKey)

	return ss, err
}
