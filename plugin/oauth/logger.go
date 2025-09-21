package oauth

import (
	"sync"

	"go.uber.org/zap"
)

var (
	logger *zap.Logger
	once   sync.Once
)

// GetLogger returns a singleton logger instance
func GetLogger() *zap.Logger {
	once.Do(func() {
		var err error
		logger, err = zap.NewProduction()
		if err != nil {
			panic(err)
		}
	})
	return logger
}

// SetLogger sets a custom logger (useful for testing)
func SetLogger(l *zap.Logger) {
	logger = l
}