package device

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt"
)

type Key struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	X5T string   `json:"x5t"`
	X5C []string `json:"x5c"`
}

type keyResponse struct {
	Keys []Key `json:"keys"`
}

type Validator struct {
	*Config
	Keys map[string]*rsa.PublicKey
}

func NewValidator(cfg *Config) Validator {
	return Validator{Config: cfg}
}

func (v *Validator) Validate(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		if key, found := v.Keys[kid]; found {
			return key, nil
		}

		return nil, fmt.Errorf("unknown key id: %s", kid)
	})
	if err != nil {
		return fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid claims")
	}

	if !claims.VerifyIssuer(v.Issuer, true) {
		return fmt.Errorf("invalid issuer %s", v.Issuer)
	}
	if !claims.VerifyAudience(v.Audience, true) {
		return fmt.Errorf("invalid audience %s", v.Audience)
	}
	if err = claims.Valid(); err != nil {
		return err
	}

	return nil
}

func (v *Validator) Initialize() error {
	keys := make(map[string]*rsa.PublicKey)

	resp, err := http.Get(v.URI)
	if err != nil {
		return err
	}

	var f keyResponse
	err = json.NewDecoder(resp.Body).Decode(&f)
	if err != nil {
		return err
	}

	for _, key := range f.Keys {
		pk := rsa.PublicKey{}
		number, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return err
		}
		pk.N = new(big.Int).SetBytes(number)

		number, err = base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return err
		}

		// pad number with 0 so it becomes an uint64
		for i := len(number); i < 8; i++ {
			number = append(number, 0)
		}
		pk.E = int(binary.LittleEndian.Uint64(number))

		log.Printf("%s: %+v", key.Kid, pk)
		keys[key.Kid] = &pk
	}

	// https://www.rfc-editor.org/rfc/rfc7518#page-30

	v.Keys = keys

	return nil
}
