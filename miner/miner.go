package miner

import (
	"github.com/mattn/go-gtk/gtk"
	"os"
	"path"
	"path/filepath"
)

func CheckFolderExists(dir string, error_msg string) bool {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			dialog := gtk.NewMessageDialog(
				gtk.NewWindow(gtk.WINDOW_TOPLEVEL),
				gtk.DIALOG_MODAL,
				gtk.MESSAGE_INFO,
				gtk.BUTTONS_OK,
				error_msg)
			dialog.Run()
			dialog.Destroy()
			return false
		} else {
			// other error
		}
	}
	return true
}

func LoadAPKs(inputDir string, apks *[]string, button *gtk.Button) {
	*apks = nil
	filepath.Walk(inputDir, func(filePath string, _ os.FileInfo, _ error) error {
		if path.Ext(filePath) == ".apk" {
			*apks = append(*apks, filePath)
		}
		return nil
	})
}
