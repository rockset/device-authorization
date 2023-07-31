package device_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rockset/device-authorization"
)

var integrationFlag = flag.Bool("integration", false, "only perform local tests")

func integration(t *testing.T) {
	if !*integrationFlag {
		t.Skipf("skipping integration test")
	}
}

func TestAuth0Auth(t *testing.T) {
	integration(t)
	ctx := context.TODO()
	p := device.NewProvider("auth0")

	a := device.NewAuthorizer(p.Config("rockset", os.Getenv("AUTH0_CLIENT_ID")))

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

func TestOktaAuth(t *testing.T) {
	integration(t)
	ctx := context.TODO()
	p := device.NewProvider("okta")
	a := device.NewAuthorizer(p.Config("rockset", os.Getenv("OKTA_CLIENT_ID")))

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
