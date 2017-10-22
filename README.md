# googleid

Package `googleid` providers helpers and wrappers for using the [`github.com/coreos/go-oidc`](https://github.com/coreos/go-oidc) library to decode and verify OpenID Connect tokens from Google.

## Usage

To decode a token, use the `googleid.Decode` function:

```go
// string representation of the JWT
var token string
payload, err := googleid.Decode(token)
// handle error
// payload is now a struct containing interesting fields from the JWT
```

**Note:** `googleid.Decode` _does not_ verify that the JWT signature is valid. It only parses the token into a struct.

To verify a token is valid, use the `googleid.Verify` function:

```go
ctx := context.Background()
// string representation of the JWT
var token string
// list of client IDs to accept JWTs for
// will be matched against the token's audience
var clientIDs []string
// an *oidc.IDTokenVerifier
// will be used to verify the token
provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
// handle err
verifier := provider.Verifier(&oidc.Config{
	SkipClientIDCheck: true, // we check against an array of ClientIDs in the googleid package
})

err = googleid.Verify(ctx, token, clientIDs, verifier)
// handle err
// if err is nil, the token is valid
```

**Note:** `googleid.Verify` _does not_ do nonce validation, which is the caller's responsibility.
