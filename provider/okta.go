package provider

import (
	"fmt"

	"golang.org/x/oauth2"
)

func NewAuth0(org, clientID string) oauth2.Config {
	return oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s.auth0.com/oauth2/v1/device/authorize", org),
			TokenURL: fmt.Sprintf("https://%s.auth0.com/oauth2/v1/token", org),
		},
		Scopes: DefaultScopes,
	}
}
