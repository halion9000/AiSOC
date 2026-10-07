package serviceauth

import (
	"os"
	"testing"
)

// unsetForTest removes an environment variable for the duration of a test and restores it afterwards (t.Setenv can only set).
func unsetForTest(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}
