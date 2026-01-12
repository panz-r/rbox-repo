package temp

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/panz/openroutertest/internal/dsl"
)

func TestTempFileTracker(t *testing.T) {
	config := &dsl.TempConfig{
		Pattern:     "/tmp/readonlybox_*",
		MaxSize:     "1MB",
		MaxCount:    10,
		AutoCleanup: "1h",
	}

	tracker := NewTempFileTracker(config)
	defer tracker.StopAutoCleanup()

	// Test registration
	tempFile, err := ioutil.TempFile("", "readonlybox_test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Write([]byte("test content"))
	tempFile.Close()

	fileInfo, err := os.Stat(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	err = tracker.RegisterTempFile(tempFile.Name(), fileInfo.Size())
	if err != nil {
		t.Fatalf("Failed to register temp file: %v", err)
	}

	// Test retrieval
	info, exists := tracker.GetTempFileInfo(tempFile.Name())
	if !exists {
		t.Error("Expected temp file to be registered")
	} else {
		if info.Path != tempFile.Name() {
			t.Errorf("Expected path %s, got %s", tempFile.Name(), info.Path)
		}
		if !info.CreatedByUs {
			t.Error("Expected CreatedByUs to be true")
		}
	}

	// Test removal
	success := tracker.RemoveTempFile(tempFile.Name())
	if !success {
		t.Error("Expected temp file to be removed successfully")
	}

	_, exists = tracker.GetTempFileInfo(tempFile.Name())
	if exists {
		t.Error("Expected temp file to be removed")
	}
}

func TestTempFileValidation(t *testing.T) {
	config := &dsl.TempConfig{
		Pattern:  "/tmp/readonlybox_*",
		MaxSize:  "1KB",
		MaxCount: 2,
	}

	tracker := NewTempFileTracker(config)
	defer tracker.StopAutoCleanup()

	// Test pattern validation
	tempFile, err := ioutil.TempFile("", "other_prefix_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Write([]byte("test"))
	tempFile.Close()

	fileInfo, _ := os.Stat(tempFile.Name())
	err = tracker.RegisterTempFile(tempFile.Name(), fileInfo.Size())
	if err == nil {
		t.Error("Expected error for non-matching pattern")
	}

	// Test size validation
	tempFile2, err := ioutil.TempFile("", "readonlybox_test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile2.Name())

	// Write more than 1KB
	largeContent := make([]byte, 2048)
	tempFile2.Write(largeContent)
	tempFile2.Close()

	fileInfo2, _ := os.Stat(tempFile2.Name())
	err = tracker.RegisterTempFile(tempFile2.Name(), fileInfo2.Size())
	if err == nil {
		t.Error("Expected error for oversized file")
	}

	// Test count validation
	// Register max count files
	for i := 0; i < config.MaxCount; i++ {
		tempFileN, _ := ioutil.TempFile("", "readonlybox_test_*.txt")
		tempFileN.Write([]byte("test"))
		tempFileN.Close()
		fileInfoN, _ := os.Stat(tempFileN.Name())
		tracker.RegisterTempFile(tempFileN.Name(), fileInfoN.Size())
		defer os.Remove(tempFileN.Name())
	}

	// Try to register one more
	tempFileExtra, _ := ioutil.TempFile("", "readonlybox_test_*.txt")
	tempFileExtra.Write([]byte("test"))
	tempFileExtra.Close()
	fileInfoExtra, _ := os.Stat(tempFileExtra.Name())
	err = tracker.RegisterTempFile(tempFileExtra.Name(), fileInfoExtra.Size())
	if err == nil {
		t.Error("Expected error for exceeding max count")
	}
	defer os.Remove(tempFileExtra.Name())
}

func TestCreateTempFile(t *testing.T) {
	config := &dsl.TempConfig{
		Pattern:  "/tmp/readonlybox_*",
		MaxSize:  "1MB",
		MaxCount: 10,
	}

	tracker := NewTempFileTracker(config)
	defer tracker.StopAutoCleanup()

	content := []byte("test content for temp file")
	path, err := tracker.CreateTempFile("readonlybox_test_", content)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(path)

	// Verify file exists and has correct content
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}

	if string(fileContent) != string(content) {
		t.Errorf("Content mismatch. Expected: %s, Got: %s", string(content), string(fileContent))
	}

	// Verify file is registered
	info, exists := tracker.GetTempFileInfo(path)
	if !exists {
		t.Error("Expected temp file to be registered")
	} else {
		if info.Size != int64(len(content)) {
			t.Errorf("Expected size %d, got %d", len(content), info.Size)
		}
	}
}

func TestAutoCleanup(t *testing.T) {
	config := &dsl.TempConfig{
		Pattern:     "/tmp/readonlybox_*",
		MaxSize:     "1MB",
		MaxCount:    10,
		AutoCleanup: "1s", // Very short for testing
	}

	tracker := NewTempFileTracker(config)
	defer tracker.StopAutoCleanup()

	// Create a temp file
	tempFile, err := ioutil.TempFile("", "readonlybox_test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Write([]byte("test"))
	tempFile.Close()

	fileInfo, _ := os.Stat(tempFile.Name())
	tracker.RegisterTempFile(tempFile.Name(), fileInfo.Size())

	// Wait for cleanup to happen
	time.Sleep(2 * time.Second)

	// Check if file was cleaned up
	_, exists := tracker.GetTempFileInfo(tempFile.Name())
	if exists {
		t.Error("Expected temp file to be cleaned up")
	}

	// Check if file was actually removed from filesystem
	_, err = os.Stat(tempFile.Name())
	if err == nil {
		t.Error("Expected temp file to be removed from filesystem")
	}
}