package phasea

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ── Payload Registry ──

// PayloadRegistry holds all loaded payloads keyed by category.
type PayloadRegistry struct {
	entries map[string][]Payload
}

// NewPayloadRegistry creates an empty payload registry.
func NewPayloadRegistry() *PayloadRegistry {
	return &PayloadRegistry{
		entries: make(map[string][]Payload),
	}
}

// LoadPayloads walks the given directory, reads every exploits/<category>/payloads.txt,
// parses NAME|PAYLOAD|Description|Severity lines, auto-classifies tier, and returns a Registry.
func LoadPayloads(dir string) (*PayloadRegistry, error) {
	registry := NewPayloadRegistry()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read exploits dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		category := entry.Name()
		filePath := filepath.Join(dir, category, "payloads.txt")

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			// Missing payloads.txt is acceptable
			continue
		}

		if err := loadCategoryFile(registry, category, filePath); err != nil {
			return nil, fmt.Errorf("load category %q: %w", category, err)
		}
	}

	return registry, nil
}

func loadCategoryFile(registry *PayloadRegistry, category, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		payload := strings.TrimSpace(parts[1])
		desc := strings.TrimSpace(parts[2])
		severity := strings.TrimSpace(parts[3])

		if name == "" || payload == "" {
			continue
		}

		tier := classifyTier(name)
		registry.entries[category] = append(registry.entries[category], Payload{
			Name:        name,
			RawPayload:  payload,
			Category:    category,
			Tier:        tier,
			Description: desc,
			Severity:    severity,
		})
	}

	return scanner.Err()
}

// classifyTier maps a payload name to its tier using pattern heuristics.
// Priority: bypass > advanced > basic.
func classifyTier(name string) string {
	upper := strings.ToUpper(name)

	// Bypass tier patterns
	bypassPatterns := []string{
		"BYPASS", "ENCODE", "DOUBLE", "NULL", "UTF8", "UTF-8", "POLY",
		"POISON", "COMMENT", "TRUNC", "WILD", "OBFUSCAT",
	}
	for _, p := range bypassPatterns {
		if strings.Contains(upper, p) {
			return "bypass"
		}
	}

	// Advanced tier patterns
	advancedPatterns := []string{
		"UNION", "ERROR", "TIME", "BLIND", "BOOLEAN", "STACKED",
		"PARAM", "RCE", "SEP", "CLOUD", "PROTO", "PHP_", "TARGETS",
		"SHELL", "FREEMARKER", "VELOCITY", "HANDLEBARS", "JINJA", "TWIG",
		"FRAMEWORK", "EVENT", "MARKDOWN", "INFO", "BOOL", "NODE",
		"IP_", "NOSQL", "LOG4", "JNDI", "OGNL", "SPEL",
		"CRLF", "SSRF", "META", "INTERNAL",
	}
	for _, p := range advancedPatterns {
		if strings.Contains(upper, p) {
			return "advanced"
		}
	}

	return "basic"
}

// GetPayloads returns payloads filtered by category and optional tier.
// If tier is "all", returns all payloads.
// If tier is "basic", "advanced", or "bypass", returns only that tier.
func (r *PayloadRegistry) GetPayloads(category string, tierFilter string) []Payload {
	entries, ok := r.entries[category]
	if !ok {
		// Try to find by mapping from VulnTest.PayloadCat
		return nil
	}

	if tierFilter == "all" || tierFilter == "" {
		return entries
	}

	var filtered []Payload
	for _, e := range entries {
		if e.Tier == tierFilter {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// GetPayloadCategories returns all loaded category names.
func (r *PayloadRegistry) Categories() []string {
	cats := make([]string, 0, len(r.entries))
	for k := range r.entries {
		cats = append(cats, k)
	}
	return cats
}

// Count returns total payloads across all categories.
func (r *PayloadRegistry) Count() int {
	total := 0
	for _, list := range r.entries {
		total += len(list)
	}
	return total
}

// HasPayloads checks if there are payloads for a category (considering tier filter).
func (r *PayloadRegistry) HasPayloads(category string, tierFilter string) bool {
	entries, ok := r.entries[category]
	if !ok {
		return false
	}
	if tierFilter == "all" || tierFilter == "" {
		return len(entries) > 0
	}
	for _, e := range entries {
		if e.Tier == tierFilter {
			return true
		}
	}
	return false
}
