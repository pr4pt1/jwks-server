package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Server holds the signing keys and exposes the HTTP handlers.
type Server struct {
	keys []*KeyPair
}

// NewServer creates one valid key (1 hour) and one already-expired key.
func NewServer() (*Server, error) {
	valid, err := NewKeyPair(time.Hour)
	if err != nil {
		return nil, err
	}
	expired, err := NewKeyPair(-time.Hour)
	if err != nil {
		return nil, err
	}
	return &Server{keys: []*KeyPair{valid, expired}}, nil
}

// Routes registers handlers. Go 1.22+ patterns restrict methods and
// automatically return 405 for anything else.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST /auth", s.handleAuth)
	return mux
}

// handleJWKS serves only unexpired public keys.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := struct {
		Keys []JWK `json:"keys"`
	}{Keys: []JWK{}}
	for _, k := range s.keys {
		if !k.Expired() {
			set.Keys = append(set.Keys, k.JWK())
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// handleAuth mocks authentication and returns a signed JWT.
// With ?expired present, it signs with the expired key and its expired exp.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	key := s.pick(r.URL.Query().Has("expired"))
	if key == nil {
		http.Error(w, "no suitable key", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": "fakeUser",
		"iat": time.Now().Unix(),
		"exp": key.Expiry.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID // lets verifiers find the right key in the JWKS

	signed, err := tok.SignedString(key.Private)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, signed)
}

// pick returns the first key whose expired state matches wantExpired.
func (s *Server) pick(wantExpired bool) *KeyPair {
	for _, k := range s.keys {
		if k.Expired() == wantExpired {
			return k
		}
	}
	return nil
}