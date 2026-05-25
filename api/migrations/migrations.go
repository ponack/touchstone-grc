// Package migrations embeds all SQL migration files.
// Keeping the embed in this package avoids Go's restriction on ".." in
// embed paths and lets golang-migrate's iofs source consume FS directly.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
