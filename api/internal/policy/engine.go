// Package policy compiles the embedded Rego control policies once at
// startup and evaluates them against scan inputs. One Engine is shared
// across all worker goroutines; the underlying OPA AST compiler is
// safe for concurrent reads.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine holds the compiled set of all Touchstone control policies.
type Engine struct {
	compiler *ast.Compiler
}

// NewEngine walks fsys, picks up every .rego file, and compiles them
// into a single ast.Compiler. Any policy that fails to parse fails
// startup — broken control packs must never reach production.
func NewEngine(fsys fs.FS) (*Engine, error) {
	modules := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		modules[path] = string(data)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("policy: no .rego modules found")
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compile rego: %w", err)
	}

	return &Engine{compiler: compiler}, nil
}

// Decision is the canonical output shape every Touchstone control
// produces. Status maps directly onto the evidence_status enum in
// migration 002.
type Decision struct {
	Status   string           `json:"status"`
	Message  string           `json:"message,omitempty"`
	Failures []map[string]any `json:"failures,omitempty"`
}

// Evaluate runs the policy at policyPath (e.g. "soc2_2017/cc6_1.rego")
// against input and returns a canonical Decision. Evaluation errors
// surface as Status="error" so the worker can still record an
// evidence_items row instead of swallowing the failure.
func (e *Engine) Evaluate(ctx context.Context, policyPath string, input any) (*Decision, error) {
	query := pathToQuery(policyPath)

	r := rego.New(
		rego.Query(query),
		rego.Compiler(e.compiler),
		rego.Input(input),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("eval %s: %w", policyPath, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return &Decision{Status: "not_applicable", Message: "no policy result"}, nil
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	if d.Status == "" {
		d.Status = "not_applicable"
	}
	return &d, nil
}

// pathToQuery turns a policy_path into the OPA query that selects the
// decision document. "soc2_2017/cc6_1.rego" -> "data.soc2_2017.cc6_1".
func pathToQuery(policyPath string) string {
	p := strings.TrimSuffix(policyPath, ".rego")
	p = strings.ReplaceAll(p, "/", ".")
	return "data." + p
}
