package release

import "testing"

func TestDefaultKeysParse(t *testing.T) {
	keys, err := DefaultKeys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatalf("got %d trusted keys, want one", len(keys))
	}
}
