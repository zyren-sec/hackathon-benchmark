package waf

import (
	"regexp"
	"strings"
)

// MarkerPattern is the regex pattern for detecting proof markers
// Pattern: __[VL]\d+[a-b]?_\w+__
// Examples: __V01_SQLI__, __L01_STACKTRACE__, __V14a_ERROR__, __CANARY_TEST__
const MarkerPattern = `__[VL]\d+[a-b]?_\w+__`

// Pre-compiled regex for marker detection
var markerRegex = regexp.MustCompile(MarkerPattern)

// DetectMarkers extracts all proof markers from the response body and headers
// Returns a unique list of found markers
func DetectMarkers(body []byte, headers map[string]string) []string {
	found := make(map[string]bool)

	// Check body
	bodyMarkers := markerRegex.FindAllString(string(body), -1)
	for _, marker := range bodyMarkers {
		found[marker] = true
	}

	// Check all header values
	for _, value := range headers {
		headerMarkers := markerRegex.FindAllString(value, -1)
		for _, marker := range headerMarkers {
			found[marker] = true
		}
	}

	// Convert to slice
	var result []string
	for marker := range found {
		result = append(result, marker)
	}

	return result
}

// DetectSpecificMarker checks if a specific marker exists in the response
func DetectSpecificMarker(body []byte, headers map[string]string, marker string) bool {
	// Check body
	if strings.Contains(string(body), marker) {
		return true
	}

	// Check headers
	for _, value := range headers {
		if strings.Contains(value, marker) {
			return true
		}
	}

	return false
}

// IsVulnerabilityMarker checks if a marker indicates a vulnerability (V-prefixed)
func IsVulnerabilityMarker(marker string) bool {
	return strings.HasPrefix(marker, "__V")
}

// IsLeakMarker checks if a marker indicates an information leak (L-prefixed)
func IsLeakMarker(marker string) bool {
	return strings.HasPrefix(marker, "__L")
}

// IsCanaryMarker checks if a marker is a canary/canonical test marker
func IsCanaryMarker(marker string) bool {
	return strings.Contains(marker, "CANARY") || strings.HasPrefix(marker, "__CANARY")
}

// ExtractVulnerabilityID extracts the vulnerability ID from a marker
// e.g., "__V01_SQLI__" returns "V01"
func ExtractVulnerabilityID(marker string) string {
	if !IsVulnerabilityMarker(marker) {
		return ""
	}

	// Extract the ID part (e.g., V01, V14a)
	re := regexp.MustCompile(`__V(\d+[a-b]?)_`)
	matches := re.FindStringSubmatch(marker)
	if len(matches) > 1 {
		return "V" + matches[1]
	}
	return ""
}

// ExtractLeakID extracts the leak ID from a marker
// e.g., "__L01_STACKTRACE__" returns "L01"
func ExtractLeakID(marker string) string {
	if !IsLeakMarker(marker) {
		return ""
	}

	// Extract the ID part
	re := regexp.MustCompile(`__L(\d+)_`)
	matches := re.FindStringSubmatch(marker)
	if len(matches) > 1 {
		return "L" + matches[1]
	}
	return ""
}

// CountVulnerabilityMarkers counts how many markers are vulnerability markers
func CountVulnerabilityMarkers(markers []string) int {
	count := 0
	for _, m := range markers {
		if IsVulnerabilityMarker(m) {
			count++
		}
	}
	return count
}

// CountLeakMarkers counts how many markers are leak markers
func CountLeakMarkers(markers []string) int {
	count := 0
	for _, m := range markers {
		if IsLeakMarker(m) {
			count++
		}
	}
	return count
}

// FilterMarkersByPrefix returns only markers with the given prefix
func FilterMarkersByPrefix(markers []string, prefix string) []string {
	var result []string
	for _, m := range markers {
		if strings.HasPrefix(m, prefix) {
			result = append(result, m)
		}
	}
	return result
}

// FilterMarkersByType filters markers by type (vulnerability, leak, or all)
func FilterMarkersByType(markers []string, markerType string) []string {
	switch strings.ToLower(markerType) {
	case "vulnerability", "vuln", "v":
		var result []string
		for _, m := range markers {
			if IsVulnerabilityMarker(m) {
				result = append(result, m)
			}
		}
		return result
	case "leak", "l":
		var result []string
		for _, m := range markers {
			if IsLeakMarker(m) {
				result = append(result, m)
			}
		}
		return result
	default:
		return markers
	}
}

// ValidateMarker checks if a string matches the marker pattern
func ValidateMarker(marker string) bool {
	return markerRegex.MatchString(marker)
}

// MarkerInfo provides detailed information about a marker
type MarkerInfo struct {
	Marker       string
	Type         string // "vulnerability", "leak", or "canary"
	ID           string // V01, L01, etc.
	Description  string // The suffix part (e.g., SQLI, STACKTRACE)
}

// ParseMarkerInfo extracts detailed information from a marker
func ParseMarkerInfo(marker string) MarkerInfo {
	info := MarkerInfo{
		Marker: marker,
	}

	if IsVulnerabilityMarker(marker) {
		info.Type = "vulnerability"
		info.ID = ExtractVulnerabilityID(marker)
	} else if IsLeakMarker(marker) {
		info.Type = "leak"
		info.ID = ExtractLeakID(marker)
	} else if IsCanaryMarker(marker) {
		info.Type = "canary"
	}

	// Extract description (the part between ID and ending __)
	re := regexp.MustCompile(`__[VL]\d+[a-b]?_(\w+)__`)
	matches := re.FindStringSubmatch(marker)
	if len(matches) > 1 {
		info.Description = matches[1]
	}

	return info
}

// GroupMarkersByVulnerability groups vulnerability markers by their vulnerability ID
func GroupMarkersByVulnerability(markers []string) map[string][]string {
	groups := make(map[string][]string)
	for _, m := range markers {
		if IsVulnerabilityMarker(m) {
			id := ExtractVulnerabilityID(m)
			if id != "" {
				groups[id] = append(groups[id], m)
			}
		}
	}
	return groups
}

// GroupMarkersByLeak groups leak markers by their leak ID
func GroupMarkersByLeak(markers []string) map[string][]string {
	groups := make(map[string][]string)
	for _, m := range markers {
		if IsLeakMarker(m) {
			id := ExtractLeakID(m)
			if id != "" {
				groups[id] = append(groups[id], m)
			}
		}
	}
	return groups
}
