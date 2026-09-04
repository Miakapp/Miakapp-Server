package main

import "testing"

func TestRunReturnsFailureForInvalidConfiguration(t *testing.T) {
	t.Setenv("MIAKAPP_LISTEN_ADDRESS", "")
	if exitCode := run(); exitCode != 1 {
		t.Fatalf("expected configuration failure exit code 1, received %d", exitCode)
	}
}
