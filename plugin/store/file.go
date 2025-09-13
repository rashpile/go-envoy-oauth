package store

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// KeySource is an interface for retrieving username by API key
type KeySource interface {
	GetUsername(apiKey string) (string, error)
}

// FileKeySource implements KeySource interface and reads key:username mappings from a file
type FileKeySource struct {
	filePath      string
	keyMap        map[string]string
	lastModified  time.Time
	checkInterval time.Duration
	mutex         sync.RWMutex
}

// NewFileKeySource creates a new FileKeySource
func NewFileKeySource(filePath string, checkInterval time.Duration) (*FileKeySource, error) {
	source := &FileKeySource{
		filePath:      filePath,
		keyMap:        make(map[string]string),
		checkInterval: checkInterval,
	}

	// Initial load of keys
	if err := source.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load keys from file: %w", err)
	}

	// Start background refresh if interval is positive
	if checkInterval > 0 {
		go source.refreshLoop()
	}

	return source, nil
}

// GetUsername returns the username associated with the given API key
func (s *FileKeySource) GetUsername(apiKey string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	username, exists := s.keyMap[apiKey]
	if !exists {
		return "", fmt.Errorf("invalid API key")
	}

	return username, nil
}

// loadKeys reads and parses the keys file
func (s *FileKeySource) loadKeys() error {
	file, err := os.Open(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file info for modification time
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// If file hasn't been modified since last check, skip loading
	if fileInfo.ModTime().Equal(s.lastModified) {
		return nil
	}

	// Create a new map to replace the old one
	newKeyMap := make(map[string]string)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split the line by the first colon
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format at line %d: expected 'key:username'", lineNum)
		}

		key := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])

		if key == "" || username == "" {
			return fmt.Errorf("invalid entry at line %d: both key and username must be non-empty", lineNum)
		}

		newKeyMap[key] = username
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Replace the old map with the new one
	s.mutex.Lock()
	s.keyMap = newKeyMap
	s.lastModified = fileInfo.ModTime()
	s.mutex.Unlock()

	// log.Printf("Loaded %d keys from %s", len(newKeyMap), s.filePath)
	// log.Printf("Last modified: %v", s.lastModified)
	// log.Printf("Next check in: %v", s.checkInterval)
	// log.Printf("Keys: %+v", newKeyMap)
	return nil
}

// refreshLoop periodically checks for file changes and reloads keys
func (s *FileKeySource) refreshLoop() {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.loadKeys(); err != nil {
			// Just log the error and continue using the existing keys
			// In a real implementation, you might want more sophisticated error handling
			fmt.Printf("Error refreshing keys: %v\n", err)
		}
	}
}
