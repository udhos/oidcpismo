// Package main implements the tool.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/udhos/oidcpismo/oidcpismo"
)

func main() {

	var pubKeyFile string

	flag.StringVar(&pubKeyFile, "pubKey", "key-pub.pem", "path to the public key file")
	flag.Parse()

	pubKeyPem, errRead := os.ReadFile(pubKeyFile)
	if errRead != nil {
		log.Fatalf("failed to read public key file: %s: %v", pubKeyFile, errRead)
	}

	pubKey, errParse := jwt.ParseRSAPublicKeyFromPEM(pubKeyPem)
	if errParse != nil {
		log.Fatalf("failed to parse public key: %v", errParse)
	}

	options := oidcpismo.JwtOptions{
		TenantID: "tenant-id",
		UID:      "account-id",
		Pismo: map[string]any{
			"account": map[string]any{
				"id": "account-id",
			},
		},
		PubKey:   pubKey,
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
}
