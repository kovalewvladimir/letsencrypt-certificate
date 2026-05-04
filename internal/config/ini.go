package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// iniData maps section -> key -> value.
// Section names:
//   - simple:   "log", "acme", "nic"
//   - dotted:   "notifier.telegram"
//   - named:    `certificate "my-server"`
type iniData map[string]map[string]string

func parseINI(path string) (iniData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	data := make(iniData)
	currentSection := ""

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Section header: [section] or [section "name"] or [section.sub]
		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: unclosed section header: %s", lineNum, line)
			}
			currentSection = line[1 : len(line)-1]
			if _, exists := data[currentSection]; !exists {
				data[currentSection] = make(map[string]string)
			}
			continue
		}

		// Key-value pair.
		idx := strings.Index(line, "=")
		if idx < 0 {
			return nil, fmt.Errorf("line %d: invalid syntax (no '='): %s", lineNum, line)
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		if currentSection == "" {
			return nil, fmt.Errorf("line %d: key-value before any section: %s", lineNum, line)
		}
		data[currentSection][key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return data, nil
}

// get returns a value from the parsed INI, empty string if missing.
func (d iniData) get(section, key string) string {
	if s, ok := d[section]; ok {
		return s[key]
	}
	return ""
}

// splitList splits a comma-separated value into trimmed non-empty strings.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
