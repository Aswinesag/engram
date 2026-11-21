package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distAssets embed.FS

// DistFS returns the embedded production Vite bundle rooted at dist/.
func DistFS() (fs.FS, error) {
	return fs.Sub(distAssets, "dist")
}
