[![license](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/udhos/oidcpismo/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/udhos/oidcpismo)](https://goreportcard.com/report/github.com/udhos/oidcpismo)
[![Go Reference](https://pkg.go.dev/badge/github.com/udhos/oidcpismo.svg)](https://pkg.go.dev/github.com/udhos/oidcpismo)

# oidcpismo

Package oidcpismo provides helpers for generating JWT tokens and requesting access tokens from the Pismo OIDC endpoint.

See:

https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt

https://developers.pismo.io/pismo-docs/reference/post-passport-v1-oauth2-token-1

# Synopsis

```golang
privKeyPem, errRead := os.ReadFile("key-priv.pem")

privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)

options := oidcpismo.Options{
    TokenURL: "https://sandbox.pismolabs.io/passport/v1/oauth2/token",
    Client:   http.DefaultClient,
    PrivKey:  privKey,

    TenantID: "tenant-id",
    UID:      "account-id",
    Pismo: map[string]any{
        "group": "pismo-v1:some-samplegroup:rw",
    },
    CustomClaims: map[string]any{
        "custom1":     "someValue",
        "userexample": "user@user.com",
    },

    Issuer:   "issuer",
    Subject:  "subject",
    Audience: "audience",
    Expire:   time.Hour,
}

resp, errResp := oidcpismo.GetAccessToken(context.Background(), options)
```

# Example

See the [examples/oidcpismo-client/main.go](examples/oidcpismo-client/main.go).

# Generate keys

```bash
# Generate a private key:

openssl genpkey -out key-priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Generate a public key based on the private key:

openssl rsa -in key-priv.pem -out key-pub.pem -pubout -outform PEM
```
