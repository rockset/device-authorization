package provider

import (
	"errors"

	"golang.org/x/oauth2"
)

var ErrNotFound = errors.New("provider not found")

type NewProviderFunc func(string, string) oauth2.Config

var Providers = map[string]NewProviderFunc{
	"auth0": NewAuth0,
	"okta":  NewOkta,
}
