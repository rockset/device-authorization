package device

import (
	"fmt"

	"golang.org/x/oauth2"
)

type Auth0 struct{}

func (a Auth0) Config(org, clientID string) *Config {
	return &Config{
		OAuth2Config: oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("https://%s.auth0.com/oauth/device/code", org),
				TokenURL: fmt.Sprintf("https://%s.auth0.com/oauth/token", org),
			},
			Scopes: DefaultScopes,
		},
		Audience: fmt.Sprintf("https://%s.auth0.com", org),
		Issuer:   fmt.Sprintf("https://%s.auth0.com/", org),
		URI:      fmt.Sprintf("https://%s.auth0.com/.well-known/jwks.json", org),
	}
}
