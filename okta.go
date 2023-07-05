package device

import (
	"fmt"

	"golang.org/x/oauth2"
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
		URI:      fmt.Sprintf("https://%s.okta.com/oauth2/v1/keys", org),
	}
}
