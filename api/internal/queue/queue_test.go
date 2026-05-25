package queue

import "testing"

func TestScanJobArgs_Kind(t *testing.T) {
	if got := (ScanJobArgs{}).Kind(); got != "scan" {
		t.Fatalf("ScanJobArgs.Kind() = %q, want %q", got, "scan")
	}
}

func TestScanJobArgs_InsertOpts(t *testing.T) {
	opts := (ScanJobArgs{}).InsertOpts()
	if opts.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", opts.MaxAttempts)
	}
	if opts.Priority != 1 {
		t.Errorf("Priority = %d, want 1", opts.Priority)
	}
	if opts.Queue != "default" {
		t.Errorf("Queue = %q, want %q", opts.Queue, "default")
	}
}
