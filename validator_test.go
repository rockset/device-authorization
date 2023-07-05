package device_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rockset/device-authorization"
)

func TestValidateOkta(t *testing.T) {
	token, err := os.ReadFile("testdata/okta.token")
	require.NoError(t, err)

	p := device.NewProvider("okta")
	validator := device.NewValidator(p.Config("rockset", os.Getenv("AUTH0_CLIENT_ID")))
	err = validator.Initialize()
	assert.NoError(t, err)

	err = validator.Validate(string(token))
	assert.NoError(t, err)
}

func TestValidateAuth0(t *testing.T) {
	token, err := os.ReadFile("testdata/auth0.token")
	require.NoError(t, err)

	p := device.NewProvider("auth0")
	validator := device.NewValidator(p.Config("rockset", os.Getenv("OKTA_CLIENT_ID")))
	err = validator.Initialize()
	assert.NoError(t, err)

	err = validator.Validate(string(token))
	assert.NoError(t, err)
}
