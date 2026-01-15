package temp

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/panz/openroutertest/internal/dsl"
)

type TempFileTracker struct {
	files         map[string]TempFileInfo
	config        *dsl.TempConfig
	mu            sync.Mutex
	cleanupTicker *time.Ticker
	stopCleanup   chan bool
}

type TempFileInfo struct {
	Path        string
	Size        int64
	CreatedByUs bool
	CreatedAt   time.Time
	LastUsed    time.Time
}

func NewTempFileTracker(config *dsl.TempConfig) *TempFileTracker {
	tracker := &TempFileTracker{
		files:       make(map[string]TempFileInfo),
		config:      config,
		stopCleanup: make(chan bool),
	}

	if config != nil && config.AutoCleanup != "" {
		tracker.startAutoCleanup()
	}

	return tracker
}

func (tracker *TempFileTracker) RegisterTempFile(path string, size int64) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if tracker.config != nil && tracker.config.Pattern != "" {
		matched, err := filepath.Match(tracker.config.Pattern, path)
		if err != nil {
			return fmt.Errorf("failed to match pattern: %v", err)
		}
		if !matched {
			return fmt.Errorf("path %s does not match pattern %s", path, tracker.config.Pattern)
		}
	}

	if tracker.config != nil && tracker.config.MaxCount > 0 {
		if len(tracker.files) >= tracker.config.MaxCount {
			return fmt.Errorf("maximum temp file count (%d) exceeded", tracker.config.MaxCount)
		}
	}

	if tracker.config != nil && tracker.config.MaxSize != "" {
		maxSize, err := parseSize(tracker.config.MaxSize)
		if err != nil {
			return fmt.Errorf("failed to parse max size: %v", err)
		}
		if size > maxSize {
			return fmt.Errorf("file size %d exceeds maximum %d", size, maxSize)
		}
	}

	tracker.files[path] = TempFileInfo{
		Path:        path,
		Size:        size,
		CreatedByUs: true,
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
	}

	return nil
}

func (tracker *TempFileTracker) GetTempFileInfo(path string) (TempFileInfo, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	info, exists := tracker.files[path]
	if exists {
		info.LastUsed = time.Now()
		tracker.files[path] = info
	}

	return info, exists
}

func (tracker *TempFileTracker) RemoveTempFile(path string) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if _, exists := tracker.files[path]; exists {
		delete(tracker.files, path)
		return true
	}

	return false
}

func (tracker *TempFileTracker) CleanupTempFiles() error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var errors []string

	for path := range tracker.files {
		err := os.Remove(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to remove %s: %v", path, err))
		} else {
			delete(tracker.files, path)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}

func (tracker *TempFileTracker) startAutoCleanup() {
	if tracker.config == nil || tracker.config.AutoCleanup == "" {
		return
	}

	duration, err := parseDuration(tracker.config.AutoCleanup)
	if err != nil {
		return
	}

	tracker.cleanupTicker = time.NewTicker(duration)
	go func() {
		for {
			select {
			case <-tracker.cleanupTicker.C:
				tracker.autoCleanupOldFiles()
			case <-tracker.stopCleanup:
				return
			}
		}
	}()
}

func (tracker *TempFileTracker) StopAutoCleanup() {
	if tracker.cleanupTicker != nil {
		tracker.cleanupTicker.Stop()
	}
	close(tracker.stopCleanup)
}

func (tracker *TempFileTracker) autoCleanupOldFiles() {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if tracker.config == nil || tracker.config.AutoCleanup == "" {
		return
	}

	duration, err := parseDuration(tracker.config.AutoCleanup)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-duration)
	var toRemove []string

	for path, info := range tracker.files {
		if info.LastUsed.Before(cutoff) {
			toRemove = append(toRemove, path)
		}
	}

	for _, path := range toRemove {
		os.Remove(path)
		delete(tracker.files, path)
	}
}

func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "h") {
		hours := strings.TrimSuffix(s, "h")
		var h int
		_, err := fmt.Sscanf(hours, "%dh", &h)
		if err != nil {
			return 0, err
		}
		return time.Duration(h) * time.Hour, nil
	}

	if strings.HasSuffix(s, "m") {
		minutes := strings.TrimSuffix(s, "m")
		var m int
		_, err := fmt.Sscanf(minutes, "%dm", &m)
		if err != nil {
			return 0, err
		}
		return time.Duration(m) * time.Minute, nil
	}

	if strings.HasSuffix(s, "s") {
		seconds := strings.TrimSuffix(s, "s")
		var s int
		_, err := fmt.Sscanf(seconds, "%ds", &s)
		if err != nil {
			return 0, err
		}
		return time.Duration(s) * time.Second, nil
	}

	return time.ParseDuration(s)
}

func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))

	if strings.HasSuffix(s, "KB") {
		kb := strings.TrimSuffix(s, "KB")
		var size int64
		_, err := fmt.Sscanf(kb, "%d", &size)
		if err != nil {
			return 0, err
		}
		return size * 1024, nil
	}

	if strings.HasSuffix(s, "MB") {
		mb := strings.TrimSuffix(s, "MB")
		var size int64
		_, err := fmt.Sscanf(mb, "%d", &size)
		if err != nil {
			return 0, err
		}
		return size * 1024 * 1024, nil
	}

	if strings.HasSuffix(s, "GB") {
		gb := strings.TrimSuffix(s, "GB")
		var size int64
		_, err := fmt.Sscanf(gb, "%d", &size)
		if err != nil {
			return 0, err
		}
		return size * 1024 * 1024 * 1024, nil
	}

	if strings.HasSuffix(s, "TB") {
		tb := strings.TrimSuffix(s, "TB")
		var size int64
		_, err := fmt.Sscanf(tb, "%d", &size)
		if err != nil {
			return 0, err
		}
		return size * 1024 * 1024 * 1024 * 1024, nil
	}

	var size int64
	_, err := fmt.Sscanf(s, "%d", &size)
	if err != nil {
		return 0, err
	}
	return size, nil
}

func (tracker *TempFileTracker) CreateTempFile(prefix string, content []byte) (string, error) {
	if tracker.config == nil {
		return "", fmt.Errorf("temp file configuration not available")
	}

	tempFile, err := ioutil.TempFile("", prefix+"*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	if len(content) > 0 {
		_, err = tempFile.Write(content)
		if err != nil {
			return "", fmt.Errorf("failed to write to temp file: %v", err)
		}
	}

	fileInfo, err := tempFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	err = tracker.RegisterTempFile(tempFile.Name(), fileInfo.Size())
	if err != nil {
		return "", fmt.Errorf("failed to register temp file: %v", err)
	}

	return tempFile.Name(), nil
}

func (tracker *TempFileTracker) GetTempFileCount() int {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	return len(tracker.files)
}

func (tracker *TempFileTracker) GetTempFileTotalSize() int64 {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var total int64
	for _, info := range tracker.files {
		total += info.Size
	}

	return total
}
