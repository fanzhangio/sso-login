package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	oidcp "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Token defines the token content
type Token struct {
	IDToken      string `json:"ID_Token"`
	RefreshToken string `json:"Refresh_Token"`
	Expiration   string `json:"Expiry"`
}

func setupLoginService(mux *http.ServeMux, issuer string) {
	ctx := clientCtx()
	provider, err := oidcp.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}

	// OIDC config
	oidcConfig := &oidcp.Config{
		ClientID: os.Getenv(EnvOIDCClientID),
	}
	verifier := provider.Verifier(oidcConfig)

	// Configure an OpenID Connect aware OAuth2 client.
	config := oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: os.Getenv(EnvOIDCClientSecret),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(os.Getenv(EnvPKSEndpoint), "/") + "/login/authcode",
		Scopes:       []string{oidcp.ScopeOpenID, "roles", "user_attributes"},
	}

	pksURL, err := url.Parse(os.Getenv(EnvPKSEndpoint))
	if err != nil {
		log.Fatal(err)
	}

	// Redirect handlers
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("port")
		parsed, _ := url.Parse(config.AuthCodeURL(state))
		parsed.Host = pksURL.Host
		parsed.Scheme = pksURL.Scheme
		http.Redirect(w, r, parsed.String(), http.StatusFound)
	})

	mux.HandleFunc("/login/authcode", func(w http.ResponseWriter, r *http.Request) {
		port := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		http.Redirect(w, r, "http://localhost:"+port+"/authcode?code="+code, http.StatusFound)
	})

	mux.HandleFunc("/login/token", func(w http.ResponseWriter, r *http.Request) {
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

		if err = idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := json.Marshal(&Token{
			IDToken:      rawIDToken,
			RefreshToken: refreshToken,
			Expiration:   expiration,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-type", "application/json")
		w.Write(data)
	})
}
