package fetch

import (
	"fmt"
	"sync"
	"testing"
)

func resetHTTPClientCacheForTest(t *testing.T) {
	t.Helper()
	clientCacheMu.Lock()
	clearHTTPClientCache()
	clientCacheMu.Unlock()
	t.Cleanup(func() {
		clientCacheMu.Lock()
		clearHTTPClientCache()
		clientCacheMu.Unlock()
	})
}

func TestGetHTTPClientReusesOneClientConcurrently(t *testing.T) {
	resetHTTPClientCacheForTest(t)

	const goroutineCount = 100
	clients := make([]interface{}, goroutineCount)
	var wg sync.WaitGroup
	for index := range clients {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			clients[index] = getHTTPClient("NONE")
		}(index)
	}
	wg.Wait()

	for index := 1; index < len(clients); index++ {
		if clients[index] != clients[0] {
			t.Fatal("concurrent cache miss created multiple HTTP clients for one proxy")
		}
	}
	if got := clientCacheCount.Load(); got != 1 {
		t.Fatalf("client cache count = %d, want 1", got)
	}
}

func TestHTTPClientCacheLimitIsConsistentUnderConcurrency(t *testing.T) {
	resetHTTPClientCacheForTest(t)

	const clientCount = 250
	var wg sync.WaitGroup
	for index := 0; index < clientCount; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			getHTTPClient(fmt.Sprintf("http://127.0.0.1:%d", 20000+index))
		}(index)
	}
	wg.Wait()

	mapCount := 0
	clientCache.Range(func(_, _ interface{}) bool {
		mapCount++
		return true
	})
	if mapCount > 100 {
		t.Fatalf("HTTP client cache contains %d entries, want at most 100", mapCount)
	}
	if got := int(clientCacheCount.Load()); got != mapCount {
		t.Fatalf("HTTP client cache count = %d, actual entries = %d", got, mapCount)
	}
}
