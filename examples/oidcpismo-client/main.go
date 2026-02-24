// Package main implements the tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/udhos/oidcpismo/oidcpismo"
)

func main() {

	var privKeyFile string
	var endpoint string

	flag.StringVar(&privKeyFile, "privKey", "key-priv.pem", "path to the private key file")
	flag.StringVar(&endpoint, "endpoint", "http://localhost:8080/token", "OIDC token endpoint")
	flag.Parse()

	privKeyPem, errRead := os.ReadFile(privKeyFile)
	if errRead != nil {
		log.Fatalf("failed to read private key file: %s: %v", privKeyFile, errRead)
	}

	privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)
	if errParse != nil {
		log.Fatalf("failed to parse private key: %v", errParse)
	}

	options := oidcpismo.JwtOptions{
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
		PrivKey:  privKey,
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: "audience",
		Expire:   time.Hour,
	}

	token, err := oidcpismo.NewJwt(options)
	if err != nil {
		log.Fatalf("failed to create JWT: %v", err)
	}

	log.Println("JWT token created successfully:")
	fmt.Println(token)

	// Use jwt token to get an access token from the OIDC provider.
	resp, errResp := oidcpismo.GetAccessToken(
		http.DefaultClient,
		endpoint,
		token,
	)
	if errResp != nil {
		log.Fatalf("failed to request access token: %v", errResp)
	}

	log.Println("Access token response:")
	fmt.Println(toJSON(resp))

	fmt.Println()
	fmt.Println("Use access token as Authorization header:")
	fmt.Println("Authorization: Bearer " + resp.AccessToken)
}

func toJSON(v any) string {
	jsonBytes, _ := json.MarshalIndent(v, "", "  ")
	return string(jsonBytes)
}
