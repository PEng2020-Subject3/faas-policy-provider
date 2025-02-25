package handlers

import (
	"net/http"
)

// MakeHealthHandler returns 200/OK when healthy
func MakeHealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		//log.Info("health check request")
		w.WriteHeader(http.StatusOK)
	}
}
