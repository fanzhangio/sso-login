package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// SetupMiddleware sets up reverse proxy for UAA
func SetupMiddleware(handler http.Handler) http.Handler {
	issuer := os.Getenv(EnvOIDCIssuer)
	if issuer != "" {
		issuerURL, err := url.Parse(issuer)
		if err != nil {
			panic("invalid " + EnvOIDCIssuer + ": " + err.Error())
		}
		remoteURL := &url.URL{
			Scheme: issuerURL.Scheme,
			Host:   issuerURL.Host,
		}
		proxy := httputil.NewSingleHostReverseProxy(remoteURL)
		proxy.Transport = clientTransport()
		director := proxy.Director
		proxy.Director = func(r *http.Request) {
			director(r)
			r.Header.Set("X-Forwarded-Host", r.Host)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Host = issuerURL.Host
		}
		// HACK: issuer can only be specified via uaa configuration and is not
		// derived from request. So forward headers doesn't affect the value of
		// issuer. Need to modify the response to reflect the correct value.
		// ModifyResponse is unnecessary when UAA can derive issuer from requests.
		proxy.ModifyResponse = func(r *http.Response) error {
			if strings.HasSuffix(strings.TrimRight(r.Request.URL.Path, "/"), "/.well-known/openid-configuration") {
				body, err := ioutil.ReadAll(r.Body)
				if err != nil {
					return err
				}
				r.Body.Close()

				// set original body, in case parsing failed
				r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

				var meta map[string]interface{}
				if err = json.Unmarshal(body, &meta); err != nil {
					log.Printf("invalid openid-configuration: %s", string(body))
					return nil
				}

				if err = fixOpenIDConfigURLs(meta, map[string]bool{
					"issuer":                 true,
					"authorization_endpoint": true,
					"token_endpoint":         true,
					"userinfo_endpoint":      false,
					"jwks_uri":               false,
				}, r.Request.Header.Get("X-Forwarded-Host")); err != nil {
					log.Printf("invalid openid-configuration: %v: %s", err, string(body))
					return nil
				}
				body, err = json.Marshal(meta)
				if err != nil {
					log.Printf("marshal openid-configuration fail: %v", err)
					return nil
				}
				r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			} else if r.StatusCode == http.StatusFound {
				if loc, err := r.Location(); err == nil {
					// be careful with localhost
					loc.Host = r.Request.Header.Get("X-Forwarded-Host")
					r.Header.Set("Location", loc.String())
				}
			}
			return nil
		}
		mux := http.NewServeMux()
		mux.Handle("/uaa/", proxy)
		setupLoginService(mux, issuer)
		mux.Handle("/", handler)
		return mux
	}
	return handler
}

func fixOpenIDConfigURLs(conf map[string]interface{}, keys map[string]bool, host string) error {
	for key, required := range keys {
		valRaw, ok := conf[key]
		if !ok {
			if required {
				return fmt.Errorf("missing property " + key)
			}
			continue
		}
		str, ok := valRaw.(string)
		if !ok {
			return fmt.Errorf("non-string property " + key)
		}
		parsedURL, err := url.Parse(str)
		if err != nil {
			return err
		}

		parsedURL.Host = host
		parsedURL.Scheme = "https"
		conf[key] = parsedURL.String()
	}
	return nil
}
