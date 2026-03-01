package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempEnv(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("write temp env: %v", err)
	}
	return path
}

func TestLoadDotEnv_Basic(t *testing.T) {
	path := writeTempEnv(t, "FOO=bar\nBAZ=qux\n")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if m["FOO"] != "bar" {
		t.Errorf("FOO = %q, want %q", m["FOO"], "bar")
	}
	if m["BAZ"] != "qux" {
		t.Errorf("BAZ = %q, want %q", m["BAZ"], "qux")
	}
}

func TestLoadDotEnv_SkipsCommentsAndBlankLines(t *testing.T) {
	path := writeTempEnv(t, "# comment\n\nKEY=value\n  # indented comment\n")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m))
	}
	if m["KEY"] != "value" {
		t.Errorf("KEY = %q, want %q", m["KEY"], "value")
	}
}

func TestLoadDotEnv_TrimsWhitespace(t *testing.T) {
	path := writeTempEnv(t, "  KEY  =  value  \n")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if m["KEY"] != "value" {
		t.Errorf("KEY = %q, want %q", m["KEY"], "value")
	}
}

func TestLoadDotEnv_ValueWithEquals(t *testing.T) {
	path := writeTempEnv(t, "URL=https://example.com?a=1&b=2\n")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if m["URL"] != "https://example.com?a=1&b=2" {
		t.Errorf("URL = %q, want %q", m["URL"], "https://example.com?a=1&b=2")
	}
}

func TestLoadDotEnv_SkipsLineWithoutEquals(t *testing.T) {
	path := writeTempEnv(t, "VALID=yes\nNOEQUALS\nALSO_VALID=ok\n")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
}

func TestLoadDotEnv_Empty(t *testing.T) {
	path := writeTempEnv(t, "")
	m, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(m))
	}
}

func TestLoadDotEnv_FileNotFound(t *testing.T) {
	_, err := LoadDotEnv("/nonexistent/.env")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
