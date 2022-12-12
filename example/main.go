package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/rockset/device-authorization"
)

func main() {
	ctx := context.Background()

	cfg, err := device.NewConfig("auth0", "rockset", os.Getenv("AUTH0_CLIENT_ID"))
	if err != nil {
		log.Fatalf("failed to create configuration: %v", err)
	}

	a := device.NewAuthorizer(cfg)

	code, err := a.RequestCode(ctx)
	if err != nil {
		log.Fatalf("failed to request a device code: %v", err)
	}

	fmt.Printf(`Attempting to automatically open the SSO authorization page in your default browser.
If the browser does not open or you wish to use a different device to authorize this request, open the following URL:

%s

Then enter the code:
%s
`, code.VerificationURIComplete, code.UserCode)

	token, err := a.WaitForAuthorization(ctx, code)
	if err != nil {
		log.Fatalf("failed to wait for authorization: %v", err)
	}

	fmt.Printf("Successfully logged in!\n")

	// TODO: cache the token on disk

	url := "https://internal.rockset.com/api/"
	body := bytes.NewBufferString(`{"request":"foobar"}`)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		log.Fatalf("failed to create request %v", err)
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("failed to make the HTTP request %v", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Printf("failed to close body: %v", err)
		}
	}()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("failed to read response body %v", err)
	}

	fmt.Println(string(data))
}
