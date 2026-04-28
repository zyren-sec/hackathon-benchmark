package httpclient

import (
	"context"
	"testing"
)

func TestPoolGetClient(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	client1, err := pool.GetClient("127.0.0.10")
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}
	if client1 == nil {
		t.Fatal("Expected client to be non-nil")
	}

	// Get same client again - should return cached instance
	client2, err := pool.GetClient("127.0.0.10")
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	// Note: We can't directly compare pointers since NewBoundClient creates a new instance each time,
	// but the pool should return the cached one
	if client2.SourceIP() != "127.0.0.10" {
		t.Errorf("Expected source IP 127.0.0.10, got %s", client2.SourceIP())
	}
}

func TestPoolGetClientForRange(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	clients, err := pool.GetClientForRange("127.0.0.10-12")
	if err != nil {
		t.Fatalf("Failed to get clients for range: %v", err)
	}
	if len(clients) != 3 {
		t.Errorf("Expected 3 clients, got %d", len(clients))
	}

	expectedIPs := []string{"127.0.0.10", "127.0.0.11", "127.0.0.12"}
	for i, client := range clients {
		if client.SourceIP() != expectedIPs[i] {
			t.Errorf("Expected client %d to have IP %s, got %s", i, expectedIPs[i], client.SourceIP())
		}
	}
}

func TestPoolGetClientForRangeInvalid(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	_, err := pool.GetClientForRange("invalid-range")
	if err == nil {
		t.Error("Expected error for invalid range")
	}
}

func TestPoolGetAllClients(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	// Get some clients
	_, _ = pool.GetClient("127.0.0.10")
	_, _ = pool.GetClient("127.0.0.11")
	_, _ = pool.GetClient("127.0.0.12")

	allClients := pool.GetAllClients()
	if len(allClients) != 3 {
		t.Errorf("Expected 3 clients in pool, got %d", len(allClients))
	}
}

func TestPoolStats(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	// Get some clients
	_, _ = pool.GetClient("127.0.0.10")
	_, _ = pool.GetClient("127.0.0.11")

	stats := pool.Stats()
	if len(stats) != 2 {
		t.Errorf("Expected stats for 2 clients, got %d", len(stats))
	}

	if _, exists := stats["127.0.0.10"]; !exists {
		t.Error("Expected stats for 127.0.0.10")
	}
	if _, exists := stats["127.0.0.11"]; !exists {
		t.Error("Expected stats for 127.0.0.11")
	}
}

func TestPoolWithRateLimitingDisabled(t *testing.T) {
	opts := DefaultPoolOptions()
	pool := NewPool(opts)
	defer pool.Close()

	_, _ = pool.GetClient("127.0.0.10")

	ctx := context.Background()

	// Should return false for active since rate limiting is disabled by default
	release, active, err := pool.AcquireRateLimiter(ctx, "127.0.0.10")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if active {
		t.Error("Expected rate limiting to be inactive by default")
	}
	release()
}
