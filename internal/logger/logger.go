package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log entry
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"ts"`
	Level     string                 `json:"level"`
	Message   string                 `json:"msg"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger provides structured logging with multiple outputs
type Logger struct {
	level       LogLevel
	consoleOut  io.Writer
	fileOut     io.Writer
	jsonOutput  bool
	mu          sync.Mutex
	fileHandle  *os.File
}

// Option configures a Logger
type Option func(*Logger)

// WithLevel sets the minimum log level
func WithLevel(level LogLevel) Option {
	return func(l *Logger) {
		l.level = level
	}
}

// WithConsoleOutput sets the console output writer
func WithConsoleOutput(w io.Writer) Option {
	return func(l *Logger) {
		l.consoleOut = w
	}
}

// WithFileOutput sets the file output path
func WithFileOutput(path string) Option {
	return func(l *Logger) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open log file: %v", err)
			return
		}
		l.fileOut = f
		l.fileHandle = f
	}
}

// WithJSONOutput enables JSON format for file output
func WithJSONOutput(enabled bool) Option {
	return func(l *Logger) {
		l.jsonOutput = enabled
	}
}

// New creates a new Logger with the given options
func New(opts ...Option) *Logger {
	l := &Logger{
		level:      INFO,
		consoleOut: os.Stdout,
		jsonOutput: true,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Close closes the log file if open
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fileHandle != nil {
		return l.fileHandle.Close()
	}
	return nil
}

// log writes a log entry at the specified level
func (l *Logger) log(level LogLevel, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   msg,
		Fields:    fields,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Console output (human-readable)
	if l.consoleOut != nil {
		consoleMsg := fmt.Sprintf("[%s] %s %s",
			entry.Timestamp.Format("15:04:05"),
			l.colorizeLevel(level),
			msg,
		)
		if len(fields) > 0 {
			consoleMsg += fmt.Sprintf(" %v", fields)
		}
		fmt.Fprintln(l.consoleOut, consoleMsg)
	}

	// File output (JSON)
	if l.fileOut != nil && l.jsonOutput {
		jsonData, err := json.Marshal(entry)
		if err == nil {
			fmt.Fprintln(l.fileOut, string(jsonData))
		}
	}

	// Exit on fatal
	if level == FATAL {
		os.Exit(1)
	}
}

func (l *Logger) colorizeLevel(level LogLevel) string {
	// ANSI color codes
	const (
		colorReset  = "\033[0m"
		colorGray   = "\033[90m"
		colorBlue   = "\033[34m"
		colorYellow = "\033[33m"
		colorRed    = "\033[31m"
		colorBold   = "\033[1m"
	)

	switch level {
	case DEBUG:
		return colorGray + "DEBUG" + colorReset
	case INFO:
		return colorBlue + "INFO " + colorReset
	case WARN:
		return colorYellow + "WARN " + colorReset
	case ERROR:
		return colorRed + "ERROR" + colorReset
	case FATAL:
		return colorBold + colorRed + "FATAL" + colorReset
	default:
		return level.String()
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(DEBUG, msg, f)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(INFO, msg, f)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(WARN, msg, f)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(ERROR, msg, f)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(FATAL, msg, f)
}

// WithField returns a new logger with additional persistent fields
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return l
}

// Standard logger instance (singleton pattern)
var std *Logger
var stdOnce sync.Once

// Init initializes the standard logger
func Init(opts ...Option) {
	stdOnce.Do(func() {
		std = New(opts...)
	})
}

// Get returns the standard logger instance
func Get() *Logger {
	if std == nil {
		Init()
	}
	return std
}

// Convenience functions for the standard logger
func Debug(msg string, fields ...map[string]interface{}) { Get().Debug(msg, fields...) }
func Info(msg string, fields ...map[string]interface{})  { Get().Info(msg, fields...) }
func Warn(msg string, fields ...map[string]interface{})  { Get().Warn(msg, fields...) }
func Error(msg string, fields ...map[string]interface{}) { Get().Error(msg, fields...) }
func Fatal(msg string, fields ...map[string]interface{})  { Get().Fatal(msg, fields...) }
