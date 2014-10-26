package ipconnection

import (
  "testing"
	"runtime"
	"strconv"
)

func BenchmarkSafeMap(b *testing.B) {
	b.StopTimer()
	workers := runtime.NumCPU()
	runtime.GOMAXPROCS(runtime.NumCPU())
	b.StartTimer()
	sm := New()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{}, workers)
		for n := 0; n < workers; n++ {
			go func() {
				for z := 0; z < 1e6; z++ {
					sm.Update(strconv.Itoa(z), func(val interface{}, found bool) interface{} {
						if !found {
							return 1
						}
						return val.(int) + 1
					})
				}
				done <- struct{}{}
			}()
		}
		// await completion
		for n := 0; n < workers; n++ {
			<-done
		}
	}
}

