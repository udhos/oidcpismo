// Package oidcpismo provides a library for implementing OIDC client for Pismo.
package oidcpismo

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Options defines the options for creating a JWT token.
type Options struct {
	// TokenURL is the required URL of the Pismo OIDC endpoint for requesting an access token.
	TokenURL string

	// Client is optional HTTP client for making requests to the Pismo OIDC endpoint.
	// If not provided, http.DefaultClient will be used.
	Client HTTPClient

	// PrivKey is the required RSA private key for signing the JWT token.
	PrivKey *rsa.PrivateKey

	//
	// Pismo non-standard claims
	//

	// TenantID is the required tenant_id claim for the JWT token.
	TenantID string

	// UID is the required uid claim for the JWT token, which represents the Pismo account ID.
	UID string

	// Pismo is the required map of Pismo-specific claims to include in the JWT token.
	Pismo map[string]any

	// CustomClaims is an optional map of custom claims to include in the JWT token.
	CustomClaims map[string]any // customClaims are optional

	//
	// Standard claims
	//

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
	// ErrMissingTokenURL is missing token URL
	ErrMissingTokenURL = errors.New("missing token URL")

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

// newJwt creates a new JWT token with the given options.
// See: https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt
func newJwt(options Options) (string, error) {

	// Bail out early if required fields are missing
	if options.TokenURL == "" {
		return "", ErrMissingTokenURL
	}
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

	// Default to http.DefaultClient if no client is provided
	if options.Client == nil {
		options.Client = http.DefaultClient
	}

	// This is required because Pismo expects the audience claim to be
	// a single string, not an array of strings.
	jwt.MarshalSingleStringAsArray = false

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

// HTTPClient defines the interface for making HTTP requests. This allows us to use any HTTP client that implements this interface, such as http.DefaultClient or a custom client with timeouts and retries.
type HTTPClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// getAccessToken requests an access token from the Pismo OIDC endpoint using the provided JWT token.
func getAccessToken(client HTTPClient, url string, token string) (resp Response, err error) {

	reqBody := Request{Token: token}
	jsonBody, errMarshal := json.Marshal(reqBody)
	if errMarshal != nil {
		err = errMarshal
		return
	}

	reader := bytes.NewReader(jsonBody)

	req, errReq := http.NewRequest("POST", url, reader)
	if errReq != nil {
		err = errReq
		return
	}

	req.Header.Set("Content-Type", "application/json")

	r, errDo := client.Do(req)
	if errDo != nil {
		err = errDo
		return
	}

	defer r.Body.Close()

	respBody, errRead := io.ReadAll(r.Body)
	if errRead != nil {
		err = errRead
		return
	}

	if r.StatusCode != http.StatusCreated {
		err = fmt.Errorf("unexpected status:%d body:%s", r.StatusCode, string(respBody))
		return
	}

	err = json.Unmarshal(respBody, &resp)
	return
}

// Request defines the request body for the Pismo OIDC endpoint
// when requesting an access token.
type Request struct {
	Token string `json:"token"`
}

// Response defines the response from the Pismo OIDC endpoint when
// requesting an access token.
type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
}

// GetAccessToken generates a JWT token using the provided options and
// requests an access token from the Pismo OIDC endpoint.
func GetAccessToken(options Options) (Response, error) {
	jwtToken, err := newJwt(options)
	if err != nil {
		return Response{}, err
	}

	return getAccessToken(options.Client, options.TokenURL, jwtToken)
}
