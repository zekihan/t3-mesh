package hubconfig

import (
	"reflect"
	"runtime"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(goodConfig))
	f.Add([]byte(goodConfig + "\n---\n{}\n"))
	f.Add([]byte("machines: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		defer func() {
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			if after.TotalAlloc-before.TotalAlloc > 64<<20 {
				t.Fatalf("parser allocated more than 64 MiB")
			}
		}()

		if len(data) > 1<<16 {
			t.Skip()
		}

		first, err := parseConfig(data)

		second, err2 := parseConfig(data)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(first, second) {
			t.Fatal("non-deterministic config parsing")
		}

		if err == nil && first.policyRevision() != second.policyRevision() {
			t.Fatal("non-deterministic revision")
		}
	})
}
