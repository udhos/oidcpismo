// Package oidcpismo provides a library for implementing OIDC client for Pismo.
package oidcpismo

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JwtOptions defines the options for creating a JWT token.
type JwtOptions struct {
	TenantID     string
	UID          string // Pismo account ID
	Pismo        map[string]any
	CustomClaims map[string]any // customClaims are optional

	PubKey   *rsa.PublicKey
	Issuer   string
	Subject  string
	Audience string
	Expire   time.Duration // max 1h
}

type customClaims struct {
	TenantID     string         `json:"tenant_id"`
	UID          string         `json:"uid"`
	Pismo        map[string]any `json:"pismo"`
	CustomClaims map[string]any `json:"customClaims,omitempty"`

	jwt.RegisteredClaims
}

// NewJwt creates a new JWT token with the given options.
// See: https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt
func NewJwt(options JwtOptions) (string, error) {

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
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(options.Expire)),
		},
	}

	// generate the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// sign the token using the public key
	ss, err := token.SignedString(options.PubKey)

	return ss, err
}
