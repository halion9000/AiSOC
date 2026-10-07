package serviceauth

// IngestOptions is the ingest service's policy.
//
// Everything else needs the token: /v1/ingest and /v1/ingest/batch (which trust the X-Tenant-ID header, so the token is what decides who may
// speak for a tenant) and the graph WebSocket stream (the API's proxy sends it). Exempt because they carry their own credential or are
// scraped: /health, /metrics (Prometheus), /v1/inbox/* (a per-source inbox token or signature) and /v1/ingest/k8s-audit/* (the apiserver's
// shared secret, enforced inside the handler).
func IngestOptions() Options {
	return Options{
		ServiceName:    "ingest",
		TokenEnv:       "AISOC_INGEST_SERVICE_TOKEN",
		ExemptPaths:    []string{"/health", "/metrics"},
		ExemptPrefixes: []string{"/v1/inbox/", "/v1/ingest/k8s-audit/"},
	}
}
