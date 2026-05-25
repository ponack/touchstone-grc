// Package frameworks loads control packs from the embedded filesystem,
// upserts them into the database at startup, and exposes the
// framework / control catalog over HTTP.
//
// A control pack is a YAML manifest paired with one Rego policy file
// per control. Manifests + policies live under packs/ and are
// embedded into the binary so the catalog is part of the release
// artifact, not a runtime download.
package frameworks

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pack is the on-disk shape of a control pack manifest (one YAML per
// framework under packs/).
type Pack struct {
	Code        string        `yaml:"code"`
	Name        string        `yaml:"name"`
	Version     string        `yaml:"version"`
	Description string        `yaml:"description"`
	Controls    []PackControl `yaml:"controls"`
}

// PackControl is one row inside a Pack's controls list.
type PackControl struct {
	Code        string `yaml:"code"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	PolicyPath  string `yaml:"policy_path"`
}

// ParsePack decodes raw manifest bytes and validates that every
// required field is set. Invalid packs fail loud at startup.
func ParsePack(raw []byte) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Pack) validate() error {
	if p.Code == "" {
		return errors.New("pack: code is required")
	}
	if p.Name == "" {
		return errors.New("pack: name is required")
	}
	if len(p.Controls) == 0 {
		return fmt.Errorf("pack %s: at least one control is required", p.Code)
	}
	seen := map[string]struct{}{}
	for i := range p.Controls {
		c := &p.Controls[i]
		if c.Code == "" {
			return fmt.Errorf("pack %s: control[%d]: code is required", p.Code, i)
		}
		if _, dup := seen[c.Code]; dup {
			return fmt.Errorf("pack %s: duplicate control code %q", p.Code, c.Code)
		}
		seen[c.Code] = struct{}{}
		if c.Title == "" {
			return fmt.Errorf("pack %s/%s: title is required", p.Code, c.Code)
		}
		if c.PolicyPath == "" {
			return fmt.Errorf("pack %s/%s: policy_path is required", p.Code, c.Code)
		}
		c.Severity = strings.ToLower(strings.TrimSpace(c.Severity))
		if c.Severity == "" {
			c.Severity = "medium"
		}
		switch c.Severity {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("pack %s/%s: invalid severity %q", p.Code, c.Code, c.Severity)
		}
	}
	return nil
}
