package auth

import (
	"context"
	"crypto/tls"
	"net/http"

	"golang.org/x/oauth2"
)

func clientTransport() http.RoundTripper {
	// TODO use correct CA
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func clientCtx() context.Context {
	client := &http.Client{Transport: clientTransport()}
	return context.WithValue(context.TODO(), oauth2.HTTPClient, client)
}
