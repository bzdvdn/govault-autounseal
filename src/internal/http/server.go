package http

import (
	"fmt"
	"log"
	"net/http"
)

// healthHandler provides a simple health check endpoint.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// StartHTTPServer starts the HTTP server for health checks.
func StartHTTPServer(port int) {
	http.HandleFunc("/health", healthHandler)
	log.Printf("Starting HTTP server on port %d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
