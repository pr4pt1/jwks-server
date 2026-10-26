package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	s, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           s.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("JWKS server listening on :8080")
	log.Fatal(srv.ListenAndServe())
}