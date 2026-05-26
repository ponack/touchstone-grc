package policy

import (
	"context"
	"testing"
	"testing/fstest"
)

const helloRego = `package test.hello

default status := "not_applicable"
default message := ""

status := "pass" if {
	input.value == "hello"
}

status := "fail" if {
	input.value != "hello"
}

message := "matched" if status == "pass"
message := "did not match" if status == "fail"
`

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	fsys := fstest.MapFS{
		"test/hello.rego": &fstest.MapFile{Data: []byte(helloRego)},
	}
	e, err := NewEngine(fsys)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestEvaluate_Pass(t *testing.T) {
	e := newTestEngine(t)
	d, err := e.Evaluate(context.Background(), "test/hello.rego", map[string]any{"value": "hello"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "pass" {
		t.Fatalf("status = %q, want pass", d.Status)
	}
	if d.Message != "matched" {
		t.Fatalf("message = %q, want matched", d.Message)
	}
}

func TestEvaluate_Fail(t *testing.T) {
	e := newTestEngine(t)
	d, err := e.Evaluate(context.Background(), "test/hello.rego", map[string]any{"value": "goodbye"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "fail" {
		t.Fatalf("status = %q, want fail", d.Status)
	}
}

func TestEvaluate_DefaultsToNotApplicable(t *testing.T) {
	e := newTestEngine(t)
	// Empty input — no rule fires.
	d, err := e.Evaluate(context.Background(), "test/hello.rego", map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Status != "not_applicable" {
		t.Fatalf("status = %q, want not_applicable", d.Status)
	}
}

func TestNewEngine_RejectsBadRego(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.rego": &fstest.MapFile{Data: []byte("package x\nnot valid rego at all {{")},
	}
	if _, err := NewEngine(fsys); err == nil {
		t.Fatal("NewEngine must reject malformed rego")
	}
}

func TestPathToQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"soc2_2017/cc6_1.rego", "data.soc2_2017.cc6_1"},
		{"cis_aws_v3/1.4.rego", "data.cis_aws_v3.1.4"},
	}
	for _, tc := range cases {
		if got := pathToQuery(tc.in); got != tc.want {
			t.Errorf("pathToQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
