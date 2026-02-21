package format

import "testing"

func TestBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{2048, "2.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{5 * 1024 * 1024, "5.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{3 * 1024 * 1024 * 1024, "3.0 GB"},
		{int64(1.5 * 1024 * 1024 * 1024), "1.5 GB"},
	}
	for _, tt := range tests {
		got := Bytes(tt.input)
		if got != tt.want {
			t.Errorf("Bytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
