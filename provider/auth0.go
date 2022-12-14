package provider

import (
	"fmt"

	"golang.org/x/oauth2"
)

func NewAuth0(org, clientID string) oauth2.Config {
	return oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s.auth0.com/oauth/device/code", org),
			TokenURL: fmt.Sprintf("https://%s.auth0.com/oauth/token", org),
		},
		Scopes: DefaultScopes,
	}
}
