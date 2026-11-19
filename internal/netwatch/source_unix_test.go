//go:build linux || darwin

package netwatch

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPumpSocketClosesAfterEOF(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = unix.Close(fds[1])
	if err != nil {
		_ = unix.Close(fds[0])

		t.Fatal(err)
	}

	out, err := pumpSocket(t.Context(), fds[0], "test socket")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("EOF produced a notification")
		}
	case <-time.After(time.Second):
		t.Fatal("notification channel stayed open after EOF")
	}

	_, err = unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("socket should be closed after EOF: F_GETFD error = %v", err)
	}
}
