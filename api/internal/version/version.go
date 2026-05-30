// Package version exposes the build-time version string baked into
// the touchstone binary. The /api/v1/version endpoint surfaces it
// to operators alongside the latest-release-on-GitHub poll.
//
// The string is set with -ldflags at build time. Distributions that
// don't rebuild from source ship "dev".
package version

// Build is the semver tag this binary was built from, prefixed with
// "v" (matching the git tag) — e.g. "v0.5.1". Set at compile time via
//
//	-ldflags="-X github.com/ponack/touchstone/internal/version.Build=v0.5.1"
//
// Unset builds report "dev".
var Build = "dev"
