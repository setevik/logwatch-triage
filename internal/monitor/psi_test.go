package monitor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPSI(t *testing.T) {
	content := `some avg10=2.10 avg60=0.50 avg300=0.10 total=123456
full avg10=0.30 avg60=0.05 avg300=0.01 total=7890
`
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := ReadPSI(path)
	if err != nil {
		t.Fatalf("ReadPSI: %v", err)
	}

	if stats.SomeAvg10 != 2.10 {
		t.Errorf("SomeAvg10 = %f, want 2.10", stats.SomeAvg10)
	}
	if stats.SomeAvg60 != 0.50 {
		t.Errorf("SomeAvg60 = %f, want 0.50", stats.SomeAvg60)
	}
	if stats.SomeAvg300 != 0.10 {
		t.Errorf("SomeAvg300 = %f, want 0.10", stats.SomeAvg300)
	}
	if stats.FullAvg10 != 0.30 {
		t.Errorf("FullAvg10 = %f, want 0.30", stats.FullAvg10)
	}
	if stats.FullAvg60 != 0.05 {
		t.Errorf("FullAvg60 = %f, want 0.05", stats.FullAvg60)
	}
	if stats.FullAvg300 != 0.01 {
		t.Errorf("FullAvg300 = %f, want 0.01", stats.FullAvg300)
	}
}

func TestReadPSIHighPressure(t *testing.T) {
	content := `some avg10=65.20 avg60=32.10 avg300=12.50 total=999999
full avg10=15.30 avg60=5.40 avg300=1.20 total=888888
`
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := ReadPSI(path)
	if err != nil {
		t.Fatal(err)
	}

	if stats.SomeAvg10 != 65.20 {
		t.Errorf("SomeAvg10 = %f, want 65.20", stats.SomeAvg10)
	}
	if stats.FullAvg10 != 15.30 {
		t.Errorf("FullAvg10 = %f, want 15.30", stats.FullAvg10)
	}
}

func TestReadPSIMissingFile(t *testing.T) {
	_, err := ReadPSI("/nonexistent/path/memory")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParsePSILine(t *testing.T) {
	tests := []struct {
		line              string
		avg10, avg60, avg300 float64
	}{
		{"some avg10=0.00 avg60=0.00 avg300=0.00 total=0", 0, 0, 0},
		{"full avg10=12.34 avg60=5.67 avg300=1.23 total=99999", 12.34, 5.67, 1.23},
	}

	for _, tt := range tests {
		a10, a60, a300 := parsePSILine(tt.line)
		if a10 != tt.avg10 || a60 != tt.avg60 || a300 != tt.avg300 {
			t.Errorf("parsePSILine(%q) = (%f, %f, %f), want (%f, %f, %f)",
				tt.line, a10, a60, a300, tt.avg10, tt.avg60, tt.avg300)
		}
	}
}
