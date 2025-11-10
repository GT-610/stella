package node

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel represents the severity level of log messages
type LogLevel int

const (
	// LogLevelDebug represents debug level messages
	LogLevelDebug LogLevel = iota
	// LogLevelInfo represents informational messages
	LogLevelInfo
	// LogLevelWarn represents warning messages
	LogLevelWarn
	// LogLevelError represents error messages
	LogLevelError
	// LogLevelFatal represents fatal error messages
	LogLevelFatal
)

// logLevelFromString converts a string to a LogLevel
func logLevelFromString(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	case "fatal":
		return LogLevelFatal
	default:
		return LogLevelInfo
	}
}

// Logger provides logging functionality for the node
type Logger struct {
	// Level is the minimum log level to output
	Level LogLevel

	// prefix is the prefix to use for log messages
	prefix string

	// debugLogger handles debug level messages
	debugLogger *log.Logger

	// infoLogger handles info level messages
	infoLogger *log.Logger

	// warnLogger handles warn level messages
	warnLogger *log.Logger

	// errorLogger handles error level messages
	errorLogger *log.Logger

	// fatalLogger handles fatal level messages
	fatalLogger *log.Logger
}

// NewLogger creates a new logger with the specified prefix and log level
func NewLogger(prefix string, level string) *Logger {
	logLevel := logLevelFromString(level)

	// Create loggers with different prefixes for each level
	debugLogger := log.New(os.Stdout, fmt.Sprintf("[DEBUG] %s: ", prefix), 0)
	infoLogger := log.New(os.Stdout, fmt.Sprintf("[INFO] %s: ", prefix), 0)
	warnLogger := log.New(os.Stderr, fmt.Sprintf("[WARN] %s: ", prefix), 0)
	errorLogger := log.New(os.Stderr, fmt.Sprintf("[ERROR] %s: ", prefix), 0)
	fatalLogger := log.New(os.Stderr, fmt.Sprintf("[FATAL] %s: ", prefix), 0)

	return &Logger{
		Level:       logLevel,
		prefix:      prefix,
		debugLogger: debugLogger,
		infoLogger:  infoLogger,
		warnLogger:  warnLogger,
		errorLogger: errorLogger,
		fatalLogger: fatalLogger,
	}
}

// formatMessage formats a log message with timestamp
func (l *Logger) formatMessage(format string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	return fmt.Sprintf("%s %s", timestamp, message)
}

// Debug logs a debug level message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.Level <= LogLevelDebug {
		l.debugLogger.Println(l.formatMessage(format, args...))
	}
}

// Info logs an info level message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.Level <= LogLevelInfo {
		l.infoLogger.Println(l.formatMessage(format, args...))
	}
}

// Warn logs a warning level message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.Level <= LogLevelWarn {
		l.warnLogger.Println(l.formatMessage(format, args...))
	}
}

// Error logs an error level message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.Level <= LogLevelError {
		l.errorLogger.Println(l.formatMessage(format, args...))
	}
}

// Fatal logs a fatal level message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	if l.Level <= LogLevelFatal {
		l.fatalLogger.Println(l.formatMessage(format, args...))
		os.Exit(1)
	}
}

// SetLevel changes the log level of the logger
func (l *Logger) SetLevel(level string) {
	l.Level = logLevelFromString(level)
	l.Info("Log level set to %s", level)
}
