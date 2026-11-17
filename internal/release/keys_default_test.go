package release

import "testing"

func TestDefaultKeysParse(t *testing.T) {
	keys, err := DefaultKeys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 {
		t.Fatalf("got %d trusted keys, want current and next", len(keys))
	}
}
