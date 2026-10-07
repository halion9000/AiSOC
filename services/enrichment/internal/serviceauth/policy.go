package serviceauth

// EnrichmentOptions is the enrichment service's policy.
//
// Everything but /health needs the token: /enrich and /enrich/bulk spend commercial threat-intel vendor quota and, through the service's
// own configured keys, query vendors on the caller's behalf.
func EnrichmentOptions() Options {
	return Options{
		ServiceName:    "enrichment",
		TokenEnv:       "AISOC_ENRICHMENT_SERVICE_TOKEN",
		ExemptPaths:    []string{"/health"},
		ExemptPrefixes: []string{},
	}
}
