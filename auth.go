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

	"github.com/rockset/device-authorization/provider"
)

type Config struct {
	OAuth2Config oauth2.Config
	client       *http.Client
}

func NewConfig(providerName, org, clientID string) (*Config, error) {
	fn, found := provider.Providers[providerName]
	if !found {
		return nil, provider.ErrNotFound
	}

	return &Config{
		OAuth2Config: fn(org, clientID),
		client:       http.DefaultClient,
	}, nil
}

type Authorizer struct {
	*Config
}

func NewAuthorizer(config *Config) *Authorizer {
	if config.client == nil {
		config.client = http.DefaultClient
	}

	return &Authorizer{
		config,
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
	return fmt.Errorf("not implemented")
}

func (a *Authorizer) Revoke(ctx context.Context) error {
	return fmt.Errorf("not implemented")
}

const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

var (
	// ErrAccessDenied is returned when the user denies the app access to their account.
	ErrAccessDenied = errors.New("access denied by user")
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

	log.Printf("http status: %s", http.StatusText(response.StatusCode))

	d := json.NewDecoder(response.Body)
	if err = d.Decode(&t); err != nil {
		return t, err
	}

	return t, nil
}

func codeRequestValues(cfg *Config) url.Values {
	return url.Values{
		"client_id": {cfg.OAuth2Config.ClientID},
		"scope":     {strings.Join(cfg.OAuth2Config.Scopes, " ")},
	}
}

func waitValues(cfg *Config, code string) url.Values {
	return url.Values{
		"client_secret": {cfg.OAuth2Config.ClientSecret},
		"client_id":     {cfg.OAuth2Config.ClientID},
		"device_code":   {code},
		"grant_type":    {GrantType},
	}
}
