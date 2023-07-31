package device

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Okta struct{}

func (o Okta) Config(org, clientID string) *Config {
	return &Config{
		OAuth2Config: oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("https://%s.okta.com/oauth2/v1/device/authorize", org),
				TokenURL: fmt.Sprintf("https://%s.okta.com/oauth2/v1/token", org),
			},
			Scopes: DefaultScopes,
		},
		Audience: fmt.Sprintf("https://%s.okta.com", org),
		Issuer:   fmt.Sprintf("https://%s.okta.com", org),
		KeyURI:   fmt.Sprintf("https://%s.okta.com/oauth2/v1/keys", org),
		client:   &http.Client{},
		org:      org,
	}
}

func NewOktaOnlineValidator(cfg *Config) *OktaOnlineValidator {
	return &OktaOnlineValidator{
		Config:           cfg,
		introspectionURI: fmt.Sprintf("https://%s.okta.com/oauth2/v1/introspect", cfg.org),
	}
}

type OktaOnlineValidator struct {
	*Config
	introspectionURI string
}

func (o *OktaOnlineValidator) Initialize(_ context.Context) error {
	return nil
}

func (o *OktaOnlineValidator) Validate(ctx context.Context, tokenString string) error {
	oir, err := o.Introspect(ctx, tokenString)
	if err != nil {
		return err
	}

	return oir.Valid(o.Config)
}

// Introspect calls the Okta OAuth2 API to validate the token, see
// https://developer.okta.com/docs/reference/api/oidc/#introspect
func (o *OktaOnlineValidator) Introspect(ctx context.Context, tokenString string) (OktaIntrospectionResponse, error) {
	// POST https://rockset.okta.com/oauth2/v1/introspect?client_id=${CLIENT_ID}&token=${TOKEN}
	var oir OktaIntrospectionResponse

	u, err := url.Parse(o.introspectionURI)
	if err != nil {
		return oir, err
	}

	values := u.Query()
	values.Set("client_id", o.OAuth2Config.ClientID)
	values.Set("token", tokenString)
	u.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(""))
	if err != nil {
		return oir, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	response, err := o.client.Do(req)
	if err != nil {
		return oir, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Printf("error closing response body: %v", err)
		}
	}()

	if response.StatusCode != http.StatusOK {
		status := response.Status
		body, err := io.ReadAll(response.Body)
		if err == nil {
			status = string(body)
		}
		return oir, fmt.Errorf("unexpected return code (%d): %s", response.StatusCode, status)
	}

	d := json.NewDecoder(response.Body)
	if err = d.Decode(&oir); err != nil {
		return oir, err
	}

	return oir, nil
}

// {
//  Active:true
//  Scope:openid profile offline_access groups
//  Username:pme@rockset.com
//  Exp:1690302787
//  Iat:1690299187
//  Sub:pme@rockset.com
//  Aud:https://rockset.okta.com
//  Iss:https://rockset.okta.com
//  Jti:AT.5mjpDSDqVSGQAgSwsEUs6ZGRWq0q2qn-sxHqMURStCw
//  TokenType:Bearer
//  ClientId:0oa6zy1dgtX2nLzKv5d7
//  Uid:00usmr7rbxb5p5b8P5d6
// }

type OktaIntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`
	Username  string `json:"username"`
	Exp       int64  `json:"exp"`
	Nbf       int64  `json:"nbf"`
	Iat       int64  `json:"iat"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Iss       string `json:"iss"`
	Jti       string `json:"jti"`
	TokenType string `json:"token_type"`
	ClientId  string `json:"client_id"`
	DeviceId  string `json:"device_id"`
	Uid       string `json:"uid"`
}

func (i OktaIntrospectionResponse) Valid(cfg *Config) error {
	if !i.Active {
		return fmt.Errorf("inactive token")
	}

	if i.ClientId != cfg.OAuth2Config.ClientID {
		return fmt.Errorf("incorrect issuer: %s", i.Iss)
	}

	if i.Aud != cfg.Audience {
		return fmt.Errorf("incorrect audience: %s", i.Aud)
	}

	t := time.Unix(i.Exp, 0)
	if time.Now().After(t) {
		return fmt.Errorf("expired: %s", t.String())
	}

	return nil
}
