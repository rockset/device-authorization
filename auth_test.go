package device_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rockset/device-authorization"
	"github.com/rockset/device-authorization/provider"
)

var integrationFlag = flag.Bool("integration", false, "only perform local tests")

func integration(t *testing.T) {
	if !*integrationFlag {
		t.Skipf("skipping integration test")
	}
}

func TestAuth0(t *testing.T) {
	integration(t)
	ctx := context.TODO()
	cfg := device.Config{
		OAuth2Config: provider.NewAuth0("rockset", os.Getenv("AUTH0_CLIENT_ID")),
	}
	a := device.NewAuthorizer(&cfg)

	code, err := a.RequestCode(ctx)
	require.NoError(t, err)
	t.Logf("%+v", code)
	t.Logf("%s %s", code.DeviceCode, code.UserCode)
	t.Logf("%s", code.VerificationURI)
	t.Logf("%s", code.VerificationURIComplete)

	token, err := a.WaitForAuthorization(ctx, code)
	require.NoError(t, err)
	t.Logf("token: %+v", token)
}

func TestOkta(t *testing.T) {
	integration(t)
	ctx := context.TODO()
	cfg := device.Config{
		OAuth2Config: provider.NewOkta("rockset", os.Getenv("OKTA_CLIENT_ID")),
	}
	a := device.NewAuthorizer(&cfg)

	code, err := a.RequestCode(ctx)
	require.NoError(t, err)
	t.Logf("%+v", code)
	t.Logf("%s %s", code.DeviceCode, code.UserCode)
	t.Logf("%s", code.VerificationURI)
	t.Logf("%s", code.VerificationURIComplete)

	token, err := a.WaitForAuthorization(ctx, code)
	require.NoError(t, err)
	t.Logf("token: %+v", token)
}
