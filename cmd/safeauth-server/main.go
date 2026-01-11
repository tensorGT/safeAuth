package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/safeauth/safeauth/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	origin := flag.String("origin", "localhost:8080", "Canonical service origin bound to signatures")
	rate := flag.Float64("rate", 20, "Per-IP rate limit (requests/sec, 0 to disable)")
	burst := flag.Int("burst", 40, "Per-IP rate limit burst size")
	flag.Parse()

	var secret []byte
	if envSecret := os.Getenv("SAFEAUTH_TOKEN_SECRET"); envSecret != "" {
		secret = []byte(envSecret)
	}

	srv, err := server.New(server.Config{
		Origin:         *origin,
		TokenSecret:    secret,
		RateLimitPerIP: *rate,
		RateBurst:      *burst,
	})
	if err != nil {
		log.Fatalf("failed to initialize auth server: %v", err)
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("safeauth-server listening on %s (origin=%s)", *addr, *origin)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
