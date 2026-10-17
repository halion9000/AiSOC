package enricher

import "testing"

// A fan-out where every provider failed (a 429 from VirusTotal, an outage) or none is configured merges to a result with no sources and a zero risk score.
// It used to be cached for the full TTL as if the indicator were clean.
func TestAnEmptyFanOutResultIsNotCached(t *testing.T) {
	empty := mergeResults(IOCTypeIP, "203.0.113.9", nil)
	if shouldCache(empty) {
		t.Fatal("a result no provider answered must not be cached as 'clean'")
	}
	if shouldCache(nil) {
		t.Fatal("nil must not be cached")
	}
}

func TestAResultAProviderAnsweredIsCached(t *testing.T) {
	answered := &EnrichmentResult{IOCType: IOCTypeIP, Value: "203.0.113.9", Sources: []EnrichmentSource{{Name: "virustotal"}}}
	if !shouldCache(answered) {
		t.Fatal("a result with at least one real source should be cached")
	}
}
