package login

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"github.com/skratchdot/open-golang/open"
)

// TODO use common configuration provider
// temporarily use environment variables

// env variables
const (
	// EnvEndpoint is environment variable to get server endpoint
	EnvEndpoint = "ENDPOINT"

	tokenFile = ".ssolib/auth/authtoken.json"
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

// SSOLogin handles Authentication and Authorization logic
func SSOLogin() error {
	endpoint := os.Getenv(EnvEndpoint)
	if endpoint == "" {
		return fmt.Errorf("require Server Endpoint")
	}

	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/authcode", func(w http.ResponseWriter, r *http.Request) {
		err := handleAuthCode(endpoint, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			errCh <- err
			return
		}
		http.Redirect(w, r, "/ok", http.StatusFound)
	})

	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Login succeeded! Please close the browser..."))
		errCh <- nil
	})

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return err
	}

	go func() {
		errCh <- http.Serve(l, mux)
	}()

	if err = open.Run(endpoint + "/login?port=" + port); err != nil {
		return err
	}

	return <-errCh
}

func handleAuthCode(endpoint, code string) error {
	resp, err := client.Get(endpoint + "/login/token?code=" + code)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, e := ioutil.ReadAll(resp.Body)
		if e == nil {
			e = errors.New(string(data))
		}
		return e
	}

	f, err := createTokenFile()
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func createTokenFile() (io.WriteCloser, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		user, err := user.Current()
		if err != nil {
			homeDir = user.HomeDir
		}
	}
	fn := filepath.Join(homeDir, tokenFile)
	dir := filepath.Dir(fn)
	err := os.MkdirAll(dir, 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	return os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
}
