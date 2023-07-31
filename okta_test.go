package device_test

import (
	"context"
	"github.com/rockset/device-authorization"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestOktaOnlineValidator(t *testing.T) {
	integration(t)

	p := device.NewProvider("okta")
	v := device.NewOktaOnlineValidator(p.Config("rockset", os.Getenv("OKTA_CLIENT_ID")))

	err := v.Validate(context.TODO(), os.Getenv("OKTA_TOKEN"))
	require.NoError(t, err)
}
