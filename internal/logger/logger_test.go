package logger

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestNewLogger(t *testing.T) {
	l := New()
	if l == nil {
		t.Fatal("Expected logger to be created")
	}
	if l.level != INFO {
		t.Errorf("Expected default level INFO, got %v", l.level)
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l := New(WithLevel(DEBUG), WithConsoleOutput(&buf))

	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")

	output := buf.String()
	if !strings.Contains(output, "debug message") {
		t.Error("Expected debug message in output")
	}
	if !strings.Contains(output, "info message") {
		t.Error("Expected info message in output")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Expected warn message in output")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Expected error message in output")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(WithLevel(WARN), WithConsoleOutput(&buf))

	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")

	output := buf.String()
	if strings.Contains(output, "debug message") {
		t.Error("Debug message should be filtered")
	}
	if strings.Contains(output, "info message") {
		t.Error("Info message should be filtered")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message should appear")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message should appear")
	}
}

func TestLogWithFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(WithConsoleOutput(&buf))

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}
	l.Info("message with fields", fields)

	output := buf.String()
	if !strings.Contains(output, "message with fields") {
		t.Error("Expected message in output")
	}
	if !strings.Contains(output, "key1") {
		t.Error("Expected field key1 in output")
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{FATAL, "FATAL"},
		{LogLevel(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestInitAndGet(t *testing.T) {
	// Reset std to test initialization
	std = nil
	stdOnce = sync.Once{}

	Init(WithLevel(DEBUG))
	l := Get()
	if l == nil {
		t.Fatal("Expected logger to be initialized")
	}
	if l.level != DEBUG {
		t.Errorf("Expected level DEBUG, got %v", l.level)
	}
}

func TestStandardLoggerFunctions(t *testing.T) {
	var buf bytes.Buffer
	std = nil
	stdOnce = sync.Once{}
	Init(WithLevel(DEBUG), WithConsoleOutput(&buf))

	Debug("test debug")
	Info("test info")
	Warn("test warn")
	Error("test error")

	output := buf.String()
	if !strings.Contains(output, "test debug") {
		t.Error("Debug output missing")
	}
	if !strings.Contains(output, "test info") {
		t.Error("Info output missing")
	}
	if !strings.Contains(output, "test warn") {
		t.Error("Warn output missing")
	}
	if !strings.Contains(output, "test error") {
		t.Error("Error output missing")
	}
}
