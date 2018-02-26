package login

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"sync"

	oidcp "github.com/coreos/go-oidc"

	"github.com/skratchdot/open-golang/open"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// TODO use common configuration provider
// temporarily use environment variables

// env variables
const (
	//Endpoint for local server
	Endpoint = "127.0.0.1:11180"
	// OIDC_ISSUER
	OIDC_ISSUER = "OIDC_ISSUER"
	// OIDC_CLIENT_ID
	OIDC_CLIENT_ID = "OIDC_CLIENT_ID"
	// OIDC_CLIENT_SECRET
	OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRET"
	// AUTH_DIR
	AUTH_DIR = "/.ssolib/auth"
	// ENDPOINT
	ENDPOINT = "ENDPOINT"

	// For prototype demo purpose
	EnvClientID      = "ssolib"
	EnvClientSecret  = "secret"
	EnvEndpointLocal = "https://localhost:8443"
)

// SSOLogin handles Authentication and Authorization logic
func SSOLogin(wg *sync.WaitGroup) error {

	l, err := net.Listen("tcp", Endpoint)
	if err != nil {
		log.Println("[Error]...Listen TCP not work !")
		log.Fatal(err)
	}

	url := "http://" + Endpoint
	err = open.Run(url)
	if err != nil {
		log.Println("[Error]... Can not open browser from local. Please check your browser settings.")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	endpoint := os.Getenv(ENDPOINT)
	if endpoint == "" {
		endpoint = EnvEndpointLocal
	}
	providerURL := os.Getenv(OIDC_ISSUER)
	if providerURL == "" {
		providerURL = endpoint + "/uaa/oauth/token"
	}
	clientID := os.Getenv(OIDC_CLIENT_ID)
	if clientID == "" {
		clientID = EnvClientID
	}
	clientSecret := os.Getenv(OIDC_CLIENT_SECRET)
	if clientSecret == "" {
		clientSecret = EnvClientSecret
	}
	provider, err := oidcp.NewProvider(ctx, providerURL)
	if err != nil {
		log.Fatal(err)
	}

	// OIDC config
	oidcConfig := &oidcp.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	// Configure an OpenID Connect aware OAuth2 client.
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:11180/authcode",
		Scopes:       []string{oidcp.ScopeOpenID, "roles", "user_attributes"},
	}

	state := "foobar"

	authDir, err := AuthDir()
	if err != nil {
		log.Printf("[Error] ... Invalid Auth directory provision, %s", err.Error())
		return err
	}

	// Redirect handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Login successfully. Please close the browser."))
		wg.Done()
	})

	http.HandleFunc("/authcode", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		refreshToken, ok := oauth2Token.Extra("refresh_token").(string)
		if !ok {
			http.Error(w, "No refresh_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		expiration := oauth2Token.Expiry.String()

		resp := struct {
			OAuth2Token   *oauth2.Token
			RawIDToken    string
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, rawIDToken, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		token := AuthToken{
			IDToken:      rawIDToken,
			RefreshToken: refreshToken,
			Expiration:   expiration,
		}

		// Save token to authtoken.json
		data, err := json.MarshalIndent(token, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = ioutil.WriteFile(authDir+"/authtoken.json", data, 0644)
		if err != nil {
			log.Printf("[Error] ... Can not save token in %s, Error : %s", authDir+"/authtoken.json", err.Error())
		}
		http.Redirect(w, r, "/success", http.StatusFound)
	})
	return http.Serve(l, nil)
}

// AuthDir provision auth home dir
func AuthDir() (string, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		user, err := user.Current()
		if err != nil {
			homeDir = user.HomeDir
		}
	}
	path := homeDir + AUTH_DIR
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err = os.MkdirAll(path, 0755); err != nil {
			return "", err
		}
	}
	return path, nil
}

type AuthToken struct {
	IDToken      string `json:"ID_Token"`
	RefreshToken string `json:"Refresh_Token"`
	Expiration   string `json:"Expiry"`
}
