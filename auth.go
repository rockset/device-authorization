package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type Config struct {
	OAuth2Config oauth2.Config
	Audience     string
	Issuer       string
	URI          string
	client       *http.Client
}

type Authorizer struct {
	*Config
	client *http.Client
}

func NewAuthorizer(config *Config) *Authorizer {
	if config.client == nil {
		config.client = http.DefaultClient
	}
	if config.Audience == "" {
		// TODO what is a good default?
		config.Audience = "something"
	}

	return &Authorizer{
		config,
		http.DefaultClient, // TODO don't!
	}
}

type Code struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type Error struct {
	ErrorCode    string   `json:"ErrorCode"`
	ErrorSummary string   `json:"errorSummary"`
	ErrorCauses  []string `json:"errorCauses"`
}

func (a *Authorizer) RequestCode(ctx context.Context) (Code, error) {
	var code Code

	resp, err := a.postForm(ctx, a.OAuth2Config.Endpoint.AuthURL, codeRequestValues(a.Config))
	if err != nil {
		return code, err
	}

	if resp.StatusCode != http.StatusOK {
		// 401 returns
		// {"error":"invalid_client","error_description":"Client authentication failed. Either the client or the client credentials are invalid."}
		body, _ := io.ReadAll(resp.Body)
		log.Println(string(body))
		return code, fmt.Errorf("device code authorization returned: %s", http.StatusText(resp.StatusCode))
	}

	d := json.NewDecoder(resp.Body)
	if err = d.Decode(&code); err != nil {
		return code, err
	}

	return code, nil
}

func (a *Authorizer) WaitForAuthorization(ctx context.Context, code Code) (oauth2.Token, error) {
	for {
		token, err := postForm[authorizationResponse](ctx,
			a.client, a.OAuth2Config.Endpoint.TokenURL, waitValues(a.Config, code.DeviceCode))
		if err != nil {
			return token.Token, err
		}

		switch token.Error {
		case "":
			// if error is empty, we got a token
			return token.Token, nil
		case "authorization_pending":
			// do nothing, just wait
		case "slow_down":
			code.Interval *= 2
		case "access_denied":
			return token.Token, ErrAccessDenied
		default:
			return token.Token, fmt.Errorf("authorization failed: %v", token.Error)
		}

		select {
		case <-ctx.Done():
			return token.Token, ctx.Err()
		case <-time.After(time.Duration(code.Interval) * time.Second):
			// next loop iteration
		}
	}
}

func (a *Authorizer) Refresh(ctx context.Context) error {
	return ErrNotImplemented
}

func (a *Authorizer) Revoke(ctx context.Context) error {
	return ErrNotImplemented
}

const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

var (
	// ErrAccessDenied is returned when the user denies the app access to their account.
	ErrAccessDenied   = errors.New("access denied by user")
	ErrAuthPending    = errors.New("authorization pending")
	ErrNotImplemented = errors.New("not implemented")
)

type authorizationResponse struct {
	oauth2.Token
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (a *Authorizer) postForm(ctx context.Context, endpoint string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return a.client.Do(req)
}

func postForm[T any](ctx context.Context, client *http.Client, endpoint string, values url.Values) (T, error) {
	var t T
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return t, err
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return t, err
	}

	// TODO what to do if the response is 5xx? then the response body won't contain anything
	//   Okta 400: {"error":"authorization_pending","error_description":"User has yet to authorize device code."}
	//   Auth0 401: {"error":"authorization_pending","error_description":"The device authorization is pending. Please try again later."}

	d := json.NewDecoder(response.Body)
	if err = d.Decode(&t); err != nil {
		return t, err
	}

	return t, nil
}

func codeRequestValues(cfg *Config) url.Values {
	values := url.Values{
		"client_id": {cfg.OAuth2Config.ClientID},
		"scope":     {strings.Join(cfg.OAuth2Config.Scopes, " ")},
	}
	if cfg.Audience != "" {
		log.Printf("setting audience: %s", cfg.Audience)
		values["audience"] = []string{cfg.Audience}
	}

	return values
}

func waitValues(cfg *Config, code string) url.Values {
	return url.Values{
		"client_secret": {cfg.OAuth2Config.ClientSecret},
		"client_id":     {cfg.OAuth2Config.ClientID},
		"device_code":   {code},
		"grant_type":    {GrantType},
	}
}
