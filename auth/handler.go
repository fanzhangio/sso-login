package auth

import "net/http"

// Handler wraps the handler with auth filters
func Handler(handler http.Handler) http.Handler {
	return SetupMiddleware(SetupFilter(handler))
}
