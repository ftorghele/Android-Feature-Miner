package miner

import (
	"github.com/mattn/go-gtk/gtk"
	"os"
	"path"
	"path/filepath"
)

func LoadAPKs(inputDir string, apks *[]string, button *gtk.Button) {
	*apks = nil
	filepath.Walk(inputDir, func(filePath string, _ os.FileInfo, _ error) error {
		if path.Ext(filePath) == ".apk" {
			*apks = append(*apks, filePath)
		}
		return nil
	})
}
