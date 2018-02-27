package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"

	oidcp "github.com/coreos/go-oidc"
	"github.com/coreos/go-oidc/oidc"
)

// TODO use common configuration provider
// temporarily use environment variables

// environment variables
const (
	EnvOIDCIssuer       = "OIDC_ISSUER"
	EnvOIDCClientID     = "OIDC_CLIENT_ID"
	EnvOIDCClientSecret = "OIDC_CLIENT_SECRET"
	EnvEndpoint         = "ENDPOINT"
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

// AuthorizationFailure provides additional info with the error
type AuthorizationFailure interface {
	StatusCode() int
}

// NewAuthenticator creates an Authenticator
func NewAuthenticator(issuer, clientID string, handler http.Handler) (*Authenticator, error) {
	provider, err := oidcp.NewProvider(clientCtx(), issuer)
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
		statusCode := http.StatusUnauthorized
		if f, ok := err.(AuthorizationFailure); ok {
			statusCode = f.StatusCode()
		}
		w.WriteHeader(statusCode)
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

	// TODO abstract this and separate the implementation
	if err = ensureAdminRole(info, r); err != nil {
		return r, err
	}

	return r.WithContext(context.WithValue(r.Context(), UserInfoCtxKey, info)), nil
}

const (
	envRolesFile     = "ROLES_FILE"
	defaultRolesFile = "roles.json"
	adminRole        = "admin"
)

// RoleMapping defines a mapping of users/groups to a role
type RoleMapping struct {
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

// RoleMappings defines mappings of roles to users/groups
type RoleMappings struct {
	Roles map[string]*RoleMapping `json:"roles"`
}

func ensureAdminRole(info *UserInfo, r *http.Request) error {
	rolesFile := os.Getenv(envRolesFile)
	if rolesFile == "" {
		rolesFile = defaultRolesFile
	}
	rolesJSON, err := ioutil.ReadFile(rolesFile)
	if err != nil {
		return err
	}
	var roles RoleMappings
	err = json.Unmarshal(rolesJSON, &roles)
	if err != nil {
		return err
	}
	if m := roles.Roles[adminRole]; m != nil {
		// make users/groups case insensitive
		for i, u := range m.Users {
			m.Users[i] = strings.ToLower(u)
		}
		for i, g := range m.Groups {
			m.Groups[i] = strings.ToLower(g)
		}
		sort.Strings(m.Users)
		sort.Strings(m.Groups)
		if sort.SearchStrings(m.Users, strings.ToLower(info.Name)) >= 0 ||
			sort.SearchStrings(m.Users, strings.ToLower(info.Email)) >= 0 {
			return nil
		}
		for _, g := range info.Groups {
			if sort.SearchStrings(m.Groups, strings.ToLower(g)) >= 0 {
				return nil
			}
		}
	}
	return &forbiddenError{}
}

type forbiddenError struct {
}

func (e *forbiddenError) Error() string {
	return "forbidden"
}

func (e *forbiddenError) StatusCode() int {
	return http.StatusForbidden
}
