package googleid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	// ErrInvalidAudience is returned when the token audience does not match the specified client IDs.
	ErrInvalidAudience = errors.New("Invalid token audience.")
)

// Token is a representation of the information encoded in a Google ID token.
type Token struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope,omitempty"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Typ   string `json:"typ,omitempty"`

	Sub           string `json:"sub,omitempty"`
	Hd            string `json:"hd,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Locale        string `json:"locale,omitempty"`

	source string
}

// Decode parses the passed payload into a Token. Note that
// Decode does not validate the Token's validity, just parses
// it into a struct.
func Decode(payload string) (*Token, error) {
	s := strings.Split(payload, ".")
	if len(s) < 2 {
		return nil, errors.New("invalid token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	t := &Token{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(t)
	if err != nil {
		return nil, err
	}
	t.source = payload
	return t, nil
}

// Verify checks that the passed token is valid, as determined
// by the passed verifier. It also checks that the token was issued
// to one of the specified client IDs. Note that Verify does not
// do nonce validation, which must be done by the caller.
func Verify(ctx context.Context, token string, clientIDs []string, verifier *oidc.IDTokenVerifier) error {
	tok, err := verifier.Verify(ctx, token)
	if err != nil {
		return err
	}
	for _, aud := range tok.Audience {
		for _, id := range clientIDs {
			if aud == id {
				return nil
			}
		}
	}
	return ErrInvalidAudience
}
