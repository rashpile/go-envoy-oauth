package filter

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func init() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Only show stack traces for Error level and above (not Warn)
	// Build with custom options to control stacktrace level
	var err error
	logger, err = config.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		panic(err)
	}
}

// GetLogger returns the configured logger instance
func GetLogger() *zap.Logger {
	return logger
}
