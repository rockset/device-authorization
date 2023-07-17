package device

var DefaultScopes = []string{"openid", "profile", "offline_access"}

type Provider interface {
	Config(org, clientID string) *Config
}

func NewProvider(name string) Provider {
	switch name {
	case "okta":
		return Okta{}
	case "auth0":
		return Auth0{}
	default:
		panic("provider not found")
	}
}
