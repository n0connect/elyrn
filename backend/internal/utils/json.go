package utils

import (
	"encoding/json"
	"net/http"
)

// HTTP header names and values the server and the agent both send
const (
	HeaderContentType  = "Content-Type"
	HeaderCacheControl = "Cache-Control"
	CacheNoStore       = "no-store"
	MIMEJSON           = "application/json"
	MIMEEventStream    = "text/event-stream"
)

// EncodeJSONResponse writes a JSON response with the given status code
func EncodeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set(HeaderContentType, MIMEJSON)
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
