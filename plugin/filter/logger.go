package filter

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger
var accessLogger *zap.Logger
var accessLogEnabled bool
var accessLogFormat string // "json" or "plain"

func init() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Set log level from environment variable
	logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "DEBUG":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "INFO":
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "WARN", "WARNING":
		config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "ERROR":
		config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	case "FATAL":
		config.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	default:
		// Default to INFO level if not specified or invalid
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Only show stack traces for Error level and above (not Warn)
	// Build with custom options to control stacktrace level
	var err error
	logger, err = config.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		panic(err)
	}

	// Set up access logger if ACCESS_LOG is configured
	accessLogEnv := strings.ToLower(os.Getenv("ACCESS_LOG"))
	if accessLogEnv == "json" || accessLogEnv == "plain" {
		accessLogEnabled = true
		accessLogFormat = accessLogEnv

		if accessLogEnv == "json" {
			// Create a logger for JSON format access logs
			accessConfig := zap.NewProductionConfig()
			accessConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
			accessConfig.EncoderConfig.TimeKey = "time"
			accessConfig.EncoderConfig.MessageKey = "msg"
			accessConfig.EncoderConfig.LevelKey = ""  // Don't show level for access logs
			accessConfig.EncoderConfig.CallerKey = "" // Don't show caller for access logs
			accessConfig.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
			accessConfig.OutputPaths = []string{"stdout"}

			accessLogger, err = accessConfig.Build()
			if err != nil {
				panic(err)
			}
		}
		// For plain format, we'll use fmt.Printf directly in LogAccess
	}
}

// GetLogger returns the configured logger instance
func GetLogger() *zap.Logger {
	return logger
}

// LogAccess logs HTTP access information if access logging is enabled
func LogAccess(method, path, host, clientIP, userAgent string, statusCode int, responseTime float64) {
	if !accessLogEnabled {
		return
	}

	// If client IP is empty, show "-"
	if clientIP == "" {
		clientIP = "-"
	}

	if accessLogFormat == "json" {
		// JSON format with all fields as separate JSON properties
		message := fmt.Sprintf("%s | %s | %s %s", host, clientIP, method, path)
		accessLogger.Info(message,
			zap.Int("status", statusCode),
			zap.Float64("response_time_ms", responseTime),
			zap.String("client_ip", clientIP),
			zap.String("user_agent", userAgent),
		)
	} else if accessLogFormat == "plain" {
		// Plain format: 2025-09-23T13:45:01Z | local.home:8081 | GET /test | 200 | 0.78
		timestamp := time.Now().UTC().Format(time.RFC3339)
		fmt.Printf("%s | %s | %s %s | %d | %.2f\n",
			timestamp, host, method, path, statusCode, responseTime)
	}
}

// IsAccessLogEnabled returns whether access logging is enabled
func IsAccessLogEnabled() bool {
	return accessLogEnabled
}

// sanitizePathForLogging removes sensitive data from URLs before logging
func sanitizePathForLogging(path string) string {
	if path == "" {
		return path
	}

	// Check if path contains query string
	idx := strings.Index(path, "?")
	if idx < 0 {
		return path // No query string, safe to log
	}

	basePath := path[:idx]
	query := path[idx+1:]

	// Parse query parameters
	values, err := url.ParseQuery(query)
	if err != nil {
		return basePath + "?[invalid_query]"
	}

	// List of sensitive parameters to redact
	sensitiveParams := []string{
		"auth-api-key",
		"api-key",
		"token",
		"access_token",
		"refresh_token",
		"id_token",
		"client_secret",
		"password",
	}

	// Redact sensitive parameters
	for _, param := range sensitiveParams {
		if values.Has(param) {
			values.Set(param, "[REDACTED]")
		}
	}

	// Rebuild the query string
	sanitizedQuery := values.Encode()
	if sanitizedQuery != "" {
		return basePath + "?" + sanitizedQuery
	}
	return basePath
}
