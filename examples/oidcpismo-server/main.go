// Package main implements the tool.
package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/udhos/boilerplate/envconfig"
	"github.com/udhos/oidcpismo/oidcpismo"
)

type application struct {
	pubKey *rsa.PublicKey
}

func main() {
	env := envconfig.NewSimple("oidcpismo-server")

	addr := env.String("ADDR", ":8080")
	pathToken := env.String("ROUTE", "/token")
	health := env.String("HEALTH", "/health")
	pubKeyFile := env.String("PUBKEY", "key-pub.pem")

	pubKeyPem, errRead := os.ReadFile(pubKeyFile)
	if errRead != nil {
		log.Fatalf("failed to read public key file: PUBKEY='%s': %v", pubKeyFile, errRead)
	}

	pubKey, errParse := jwt.ParseRSAPublicKeyFromPEM(pubKeyPem)
	if errParse != nil {
		log.Fatalf("failed to parse public key: %v", errParse)
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	app := &application{
		pubKey: pubKey,
	}

	const root = "/"

	register(mux, addr, root, handlerRoot)
	register(mux, addr, health, handlerHealth)
	register(mux, addr, pathToken, func(w http.ResponseWriter, r *http.Request) { handlerToken(w, r, app) })

	go listenAndServe(server, addr)

	select {} // wait forever
}

func register(mux *http.ServeMux, addr, path string, handler http.HandlerFunc) {
	mux.HandleFunc(path, handler)
	log.Printf("registered on port %s path %s", addr, path)
}

func listenAndServe(s *http.Server, addr string) {
	log.Printf("listening on port %s", addr)
	err := s.ListenAndServe()
	log.Fatalf("listening on port %s: %v", addr, err)
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

func response(w http.ResponseWriter, r *http.Request, status int, message string) {
	hostname, errHost := os.Hostname()
	if errHost != nil {
		log.Printf("hostname error: %v", errHost)
	}
	reply := fmt.Sprintf(`{"message":"%s","status":"%d","path":"%s","method":"%s","host":"%s","serverHostname":"%s"}`,
		message, status, r.RequestURI, r.Method, r.Host, hostname)
	httpJSON(w, reply, status)
}

func handlerRoot(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s - 404 not found", r.RemoteAddr, r.Method, r.RequestURI)
	response(w, r, http.StatusNotFound, "not found")
}

func handlerHealth(w http.ResponseWriter, r *http.Request) {
	response(w, r, http.StatusOK, "health ok")
}

func handlerToken(w http.ResponseWriter, r *http.Request, app *application) {

	// read body

	body, errRead := io.ReadAll(r.Body)
	if errRead != nil {
		log.Printf("%s %s %s - body read error - 500 server error: %v",
			r.RemoteAddr, r.Method, r.RequestURI, errRead)
		response(w, r, http.StatusInternalServerError, "server error")
		return
	}

	// parse request

	var tokReq oidcpismo.Request
	errUnmarshal := json.Unmarshal(body, &tokReq)
	if errUnmarshal != nil {
		log.Printf("%s %s %s - body unmarshal error - 400 bad request: %v",
			r.RemoteAddr, r.Method, r.RequestURI, errUnmarshal)
		response(w, r, http.StatusBadRequest, "bad request")
		return
	}

	// parse jwt token

	tk, errParse := jwt.Parse(tokReq.Token, func(_ *jwt.Token) (any, error) {
		return app.pubKey, nil
	})
	if errParse != nil {
		log.Printf("%s %s %s - token parse error - 400 bad request: %v",
			r.RemoteAddr, r.Method, r.RequestURI, errParse)
		response(w, r, http.StatusBadRequest, "bad request")
		return
	}

	if !tk.Valid {
		log.Printf("%s %s %s - invalid token - 401 unauthorized", r.RemoteAddr, r.Method, r.RequestURI)
		response(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	exp, errExp := tk.Claims.GetExpirationTime()
	if errExp != nil {
		log.Printf("%s %s %s - token expiration time error - 400 bad request: %v",
			r.RemoteAddr, r.Method, r.RequestURI, errExp)
		response(w, r, http.StatusBadRequest, "bad request")
		return
	}

	// calculate remaining time until token expiration

	now := time.Now()
	if exp.Before(now) {
		log.Printf("%s %s %s - token expired - 401 unauthorized", r.RemoteAddr, r.Method, r.RequestURI)
		response(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	remaining := exp.Sub(now)
	log.Printf("%s %s %s - token valid - remaining time until expiration: %v", r.RemoteAddr, r.Method, r.RequestURI, remaining)

	// create access token

	accessToken, errToken := newToken(int(remaining.Seconds()))
	if errToken != nil {
		log.Printf("%s %s %s - token creation error - 500 server error: %v",
			r.RemoteAddr, r.Method, r.RequestURI, errToken)
		response(w, r, http.StatusInternalServerError, "server error")
		return
	}

	// reply with access token

	var resp oidcpismo.Response
	resp.AccessToken = accessToken
	resp.ExpiresIn = fmt.Sprint(int(remaining.Seconds()))
	resp.RefreshToken = "some-refresh-token"
	data, err := json.Marshal(&resp)
	if err != nil {
		log.Printf("%s %s %s - response marshal error - 500 server error: %v",
			r.RemoteAddr, r.Method, r.RequestURI, err)
		response(w, r, http.StatusInternalServerError, "server error")
		return
	}

	log.Printf("%s %s %s - 201 ok", r.RemoteAddr, r.Method, r.RequestURI)

	httpJSON(w, string(data), http.StatusCreated)
}

var sampleSecretKey = []byte("mysecretkey")

func newToken(exp int) (string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	claims := accessToken.Claims.(jwt.MapClaims)
	now := time.Now()
	claims["iat"] = now.Unix()
	if exp > 0 {
		claims["exp"] = now.Add(time.Duration(exp) * time.Second).Unix()
	}

	str, errSign := accessToken.SignedString(sampleSecretKey)
	if errSign != nil {
		return "", errSign
	}
	return str, nil
}
