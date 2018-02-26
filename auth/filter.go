package auth

import (
	"context"
	"net/http"
	"os"

	oidcp "github.com/coreos/go-oidc"
	"github.com/coreos/go-oidc/oidc"
)

// TODO use common configuration provider
// temporarily use environment variables

// environment variables
const (
	EnvOIDCIssuer   = "OIDC_ISSUER"
	EnvOIDCClientID = "OIDC_CLIENT_ID"
)

// SetupFilter creates authorization filter wrapping handler
func SetupFilter(handler http.Handler) http.Handler {
	issuer := os.Getenv(EnvOIDCIssuer)
	if issuer != "" {
		clientID := os.Getenv(EnvOIDCClientID)
		if clientID == "" {
			panic("OIDC_CLIENT_ID is required")
		}
		authn, err := NewAuthenticator(issuer, clientID, handler)
		if err != nil {
			// failfast here
			panic(err)
		}
		return authn
	}
	return handler
}

// UserInfo provides user information
type UserInfo struct {
	Name   string   `json:"user_name"`
	Email  string   `json:"email"`
	Groups []string `json:"roles"`
}

// UserInfoCtxKey defines key of context
var UserInfoCtxKey interface{} = "userinfo"

// UserInfoFromCtx is a helper to extract user info from context
func UserInfoFromCtx(ctx context.Context) *UserInfo {
	v := ctx.Value(UserInfoCtxKey)
	if v != nil {
		if info, ok := v.(*UserInfo); ok {
			return info
		}
	}
	return nil
}

// Authenticator providers http.Handler to perform authorization
type Authenticator struct {
	NextHandler http.Handler

	provider *oidcp.Provider
	verifier *oidcp.IDTokenVerifier
}

// NewAuthenticator creates an Authenticator
func NewAuthenticator(issuer, clientID string, handler http.Handler) (*Authenticator, error) {
	provider, err := oidcp.NewProvider(context.TODO(), issuer)
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		NextHandler: handler,
		provider:    provider,
		verifier:    provider.Verifier(&oidcp.Config{ClientID: clientID}),
	}, nil
}

// ServeHTTP implements http.Handler
func (a *Authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, err := a.authorize(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
	} else {
		a.NextHandler.ServeHTTP(w, r)
	}
}

func (a *Authenticator) authorize(r *http.Request) (*http.Request, error) {
	token, err := oidc.ExtractBearerToken(r)
	if err != nil {
		return r, err
	}
	idToken, err := a.verifier.Verify(r.Context(), token)
	if err != nil {
		return r, err
	}

	info := &UserInfo{}
	if err = idToken.Claims(info); err != nil {
		return r, err
	}

	return r.WithContext(context.WithValue(r.Context(), UserInfoCtxKey, info)), nil
}
