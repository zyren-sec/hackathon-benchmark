package httpclient

import (
	"testing"
)

func TestBoundClientCreation(t *testing.T) {
	opts := DefaultClientOptions()
	client, err := NewBoundClient("127.0.0.20", opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if client.SourceIP() != "127.0.0.20" {
		t.Errorf("Expected source IP 127.0.0.20, got %s", client.SourceIP())
	}
}

func TestBoundClientInvalidIP(t *testing.T) {
	opts := DefaultClientOptions()
	_, err := NewBoundClient("not-an-ip", opts)
	if err == nil {
		t.Error("Expected error for invalid IP address")
	}
}

func TestBoundClientStats(t *testing.T) {
	opts := ClientOptions{
		Timeout:   5000 * 1000000, // 5 seconds in nanoseconds
		UserAgent: "TestAgent/1.0",
	}
	client, err := NewBoundClient("127.0.0.30", opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	stats := client.Stats()
	if stats["source_ip"] != "127.0.0.30" {
		t.Errorf("Expected source_ip 127.0.0.30, got %v", stats["source_ip"])
	}
	if stats["user_agent"] != "TestAgent/1.0" {
		t.Errorf("Expected user_agent TestAgent/1.0, got %v", stats["user_agent"])
	}
}

func TestMultipleBoundClients(t *testing.T) {
	opts := DefaultClientOptions()

	// Create clients for multiple IPs
	ips := []string{"127.0.0.10", "127.0.0.11", "127.0.0.12"}
	clients := make([]*BoundClient, len(ips))

	for i, ip := range ips {
		client, err := NewBoundClient(ip, opts)
		if err != nil {
			t.Fatalf("Failed to create client for %s: %v", ip, err)
		}
		clients[i] = client
		defer client.Close()
	}

	// Verify each client has correct IP
	for i, client := range clients {
		if client.SourceIP() != ips[i] {
			t.Errorf("Client %d: expected IP %s, got %s", i, ips[i], client.SourceIP())
		}
	}
}
