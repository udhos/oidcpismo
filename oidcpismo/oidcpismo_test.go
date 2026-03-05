package oidcpismo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDefaultOptions(t *testing.T) {

	privKeyFile := "../key-priv.pem"

	privKeyPem, errRead := os.ReadFile(privKeyFile)
	if errRead != nil {
		t.Fatalf("failed to read private key file: %s: %v", privKeyFile, errRead)
	}

	privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)
	if errParse != nil {
		t.Fatalf("failed to parse private key: %v", errParse)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var resp Response
		resp.Token = "access-token"
		resp.ExpiresIn = "60"
		resp.RefreshToken = "some-refresh-token"
		data, _ := json.Marshal(&resp)
		httpJSON(w, string(data), http.StatusCreated)

	}))
	defer ts.Close()

	options := Options{
		TokenURL: ts.URL,
		PrivKey:  privKey,

		//
		// These claims are non-standard claims required by Pismo.
		// See: https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt
		//
		TenantID: "tenant-id",
		UID:      "account-id",
		Pismo: map[string]any{
			"group": "pismo-v1:some-samplegroup:rw",
		},
		// Only CustomClaims is optional, you can omit it if you don't need to add custom claims.
		CustomClaims: map[string]any{
			"custom1":     "someValue",
			"userexample": "user@user.com",
		},

		//
		// Registered claims
		//
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: "audience",
		Expire:   time.Hour,
	}

	_, errNormal := GetAccessToken(context.TODO(), options)

	if errors.Is(errNormal, err1) {
		t.Fatalf("unexpected error1: %v", errNormal)
	}

	if errors.Is(errNormal, err2) {
		t.Fatalf("unexpected error2: %v", errNormal)
	}

	options.Client = &client{}

	if _, errClient := GetAccessToken(context.TODO(), options); !errors.Is(errClient, err1) {
		t.Fatalf("unexpected client error: %v", errClient)
	}

	options.Client = nil

	options.CheckHTTPResponseStatus = func(_ int) error {
		return err2
	}

	if _, errStatus := GetAccessToken(context.TODO(), options); !errors.Is(errStatus, err2) {
		t.Fatalf("unexpected status error: %v", errStatus)
	}
}

// httpJSON replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The message should be JSON.
func httpJSON(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, message)
}

var (
	err1 = errors.New("error1")
	err2 = errors.New("error2")
)

type client struct {
}

func (c *client) Do(_ *http.Request) (resp *http.Response, err error) {
	return nil, err1
}
