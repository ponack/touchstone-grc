// Package packs holds the embedded control pack manifests + Rego
// policy files. Files are exposed as a fs.FS so the loader and the
// (future) OPA evaluator can each read what they need.
package packs

import "embed"

// FS embeds:
//   - *.yaml — one manifest per framework
//   - soc2_2017/*.rego, cis_aws_v3/*.rego, ... — one policy per control
//
//go:embed *.yaml
//go:embed soc2_2017/*.rego
var FS embed.FS
