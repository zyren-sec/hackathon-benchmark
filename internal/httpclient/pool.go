package httpclient

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/semaphore"
)

// Pool manages a collection of BoundClients for different source IPs
// This enables testing from multiple source IP addresses (127.0.0.10-99)
type Pool struct {
	clients     map[string]*BoundClient
	rateLimiters map[string]*semaphore.Weighted
	options     ClientOptions
	mu          sync.RWMutex
}

// PoolOptions contains configuration for the client pool
type PoolOptions struct {
	ClientOptions
	MaxRequestsPerSecondPerIP int
}

// DefaultPoolOptions returns default pool options
func DefaultPoolOptions() PoolOptions {
	return PoolOptions{
		ClientOptions:             DefaultClientOptions(),
		MaxRequestsPerSecondPerIP: 0, // 0 = unlimited
	}
}

// NewPool creates a new client pool
func NewPool(opts PoolOptions) *Pool {
	return &Pool{
		clients:      make(map[string]*BoundClient),
		rateLimiters: make(map[string]*semaphore.Weighted),
		options:      opts.ClientOptions,
	}
}

// GetClient returns a BoundClient for the specified source IP
// Creates a new client if one doesn't exist
func (p *Pool) GetClient(sourceIP string) (*BoundClient, error) {
	p.mu.RLock()
	client, exists := p.clients[sourceIP]
	p.mu.RUnlock()

	if exists {
		return client, nil
	}

	// Create new client
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if client, exists := p.clients[sourceIP]; exists {
		return client, nil
	}

	client, err := NewBoundClient(sourceIP, p.options)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", sourceIP, err)
	}

	p.clients[sourceIP] = client

	return client, nil
}

// AcquireRateLimiter acquires a rate limit slot for the given IP
// Returns the release function and true if rate limiting is active
func (p *Pool) AcquireRateLimiter(ctx context.Context, sourceIP string) (func(), bool, error) {
	p.mu.RLock()
	limiter, exists := p.rateLimiters[sourceIP]
	p.mu.RUnlock()

	if !exists {
		// No rate limiting for this IP
		return func() {}, false, nil
	}

	if err := limiter.Acquire(ctx, 1); err != nil {
		return nil, true, err
	}

	release := func() {
		limiter.Release(1)
	}

	return release, true, nil
}

// GetClientForRange returns clients for a range of source IPs
// ipRange format: "127.0.0.10-19"
func (p *Pool) GetClientForRange(ipRange string) ([]*BoundClient, error) {
	ips, err := ParseIPRange(ipRange)
	if err != nil {
		return nil, err
	}

	var clients []*BoundClient
	for _, ip := range ips {
		client, err := p.GetClient(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to get client for %s: %w", ip, err)
		}
		clients = append(clients, client)
	}

	return clients, nil
}

// GetAllClients returns all created clients
func (p *Pool) GetAllClients() []*BoundClient {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clients := make([]*BoundClient, 0, len(p.clients))
	for _, client := range p.clients {
		clients = append(clients, client)
	}
	return clients
}

// Close closes all clients in the pool
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	for ip, client := range p.clients {
		if err := client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close client %s: %w", ip, err))
		}
	}

	p.clients = make(map[string]*BoundClient)
	p.rateLimiters = make(map[string]*semaphore.Weighted)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing pool: %v", errs)
	}
	return nil
}

// Stats returns statistics for all clients in the pool
func (p *Pool) Stats() map[string]map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make(map[string]map[string]interface{})
	for ip, client := range p.clients {
		stats[ip] = client.Stats()
	}
	return stats
}
