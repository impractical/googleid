package googleid

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

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

func Verify(token string, keys ...*rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}

	signedContent := parts[0] + "." + parts[1]
	signatureString, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write([]byte(signedContent))
	for _, key := range keys {
		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), []byte(signatureString))
		if err == nil {
			return nil
		}
	}
	return err
}

func Valid(token Token, clientID, domain string, keys ...*rsa.PublicKey) bool {
	if token.Exp < time.Now().UTC().Unix() {
		return false
	}
	if clientID != token.Aud {
		return false
	}
	if token.Iss != "accounts.google.com" && token.Iss != "https://accounts.google.com" {
		return false
	}
	if token.Hd != "" && token.Hd != domain {
		return false
	}
	return Verify(token.source, keys...) == nil
}
