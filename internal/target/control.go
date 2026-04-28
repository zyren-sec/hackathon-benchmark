package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Control provides methods to manipulate the target application state
type Control struct {
	client *Client
}

// NewControl creates a new control interface
func NewControl(client *Client) *Control {
	return &Control{client: client}
}

// Reset resets the target application to a clean state
func (c *Control) Reset() error {
	url := fmt.Sprintf("%s/__control/reset", c.client.BaseURL)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create reset request: %w", err)
	}

	req.Header.Set("X-Benchmark-Secret", c.client.Secret)

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("reset request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reset returned status %d", resp.StatusCode)
	}

	return nil
}

// SetSlow configures the target to respond slowly
func (c *Control) SetSlow(delayMs int) error {
	url := fmt.Sprintf("%s/__control/slow", c.client.BaseURL)
	payload := map[string]int{"delay_ms": delayMs}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slow request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create slow request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Benchmark-Secret", c.client.Secret)

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("slow request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slow request returned status %d", resp.StatusCode)
	}

	return nil
}

// SetErrorMode configures the target to return errors
func (c *Control) SetErrorMode(mode string) error {
	url := fmt.Sprintf("%s/__control/error_mode", c.client.BaseURL)
	payload := map[string]string{"mode": mode}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal error_mode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create error_mode request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Benchmark-Secret", c.client.Secret)

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("error_mode request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error_mode request returned status %d", resp.StatusCode)
	}

	return nil
}

// SetHealthMode sets the health status of the target
func (c *Control) SetHealthMode(down bool) error {
	url := fmt.Sprintf("%s/__control/health_mode", c.client.BaseURL)
	payload := map[string]bool{"down": down}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal health_mode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create health_mode request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Benchmark-Secret", c.client.Secret)

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health_mode request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health_mode request returned status %d", resp.StatusCode)
	}

	return nil
}
