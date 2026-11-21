package kube

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestConfigMapWatchLimitsEachEvent(t *testing.T) {
	const (
		prefix = `{"type":"MODIFIED","object":{"metadata":{"name":"hub"},"data":{"config":"`
		suffix = `"}}}`
	)

	limit := maxConfigMapReply - len(prefix) - len(suffix)
	event := func(size int) io.Reader {
		return io.MultiReader(
			strings.NewReader(prefix),
			strings.NewReader(strings.Repeat("x", size)),
			strings.NewReader(suffix+"\n"),
		)
	}

	updates := 0
	body := io.MultiReader(event(limit), event(limit), event(limit+1), event(1))

	err := readConfigMapEvents(body, "hub", func(data map[string]string) {
		updates++

		if size := len(data["config"]); size != limit {
			t.Errorf("unexpected event with %d data bytes", size)
		}
	})
	if !errors.Is(err, bufio.ErrTooLong) || updates != 2 {
		t.Fatalf(
			"stream applied %d events and returned %v, want 2 events and size error",
			updates,
			err,
		)
	}
}
