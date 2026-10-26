package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// parse verifies a token using the server's keys, looked up by the kid header.
func parse(s *Server, token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		for _, k := range s.keys {
			if k.KID == kid {
				return &k.Private.PublicKey, nil
			}
		}
		return nil, errors.New("unknown kid")
	}, jwt.WithValidMethods([]string{"RS256"}))
}

func TestJWKSServesOnlyUnexpiredKeys(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, http.MethodGet, "/.well-known/jwks.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KID != s.keys[0].KID {
		t.Fatalf("expected only the valid key, got %+v", set.Keys)
	}
}

func TestJWKEncodingRoundTrips(t *testing.T) {
	s := newTestServer(t)
	j := s.keys[0].JWK()
	nBytes, _ := base64.RawURLEncoding.DecodeString(j.N)
	eBytes, _ := base64.RawURLEncoding.DecodeString(j.E)
	pub := rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
	if pub.N.Cmp(s.keys[0].Private.N) != 0 || pub.E != s.keys[0].Private.E {
		t.Fatal("JWK does not match the original public key")
	}
}

func TestAuthIssuesValidToken(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, http.MethodPost, "/auth")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	tok, err := parse(s, string(body))
	if err != nil || !tok.Valid {
		t.Fatalf("token should be valid: %v", err)
	}
	if tok.Header["kid"] != s.keys[0].KID {
		t.Fatal("token not signed with the valid key")
	}
}

func TestAuthExpiredQueryIssuesExpiredToken(t *testing.T) {
	s := newTestServer(t)
	rec := do(s, http.MethodPost, "/auth?expired=true")
	body, _ := io.ReadAll(rec.Body)
	tok, err := parse(s, string(body))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("expected expired error, got %v", err)
	}
	if tok.Header["kid"] != s.keys[1].KID {
		t.Fatal("token not signed with the expired key")
	}
}

func TestWrongMethodsRejected(t *testing.T) {
	s := newTestServer(t)
	if c := do(s, http.MethodGet, "/auth").Code; c != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth = %d", c)
	}
	if c := do(s, http.MethodPost, "/.well-known/jwks.json").Code; c != http.StatusMethodNotAllowed {
		t.Fatalf("POST jwks = %d", c)
	}
}