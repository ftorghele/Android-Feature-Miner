package miner

import (
	"fmt"
	"github.com/mattn/go-gtk/gtk"
	"os"
	"os/exec"
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

func StaticAnalysis(apks *[]string, progress_bar *gtk.ProgressBar) {
	for i, path := range *apks {

		wd, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}

		cmd := exec.Command(wd+"/scripts/static_analysis.py", "-i"+path, "-o"+wd+"/features/static")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}

		progress_bar.SetFraction(float64(1) / float64(len(*apks)) * float64(i+1))
		for gtk.EventsPending() {
			gtk.MainIteration()
		}
	}
}

func DynamicAnalysis(apks *[]string, progress_bar *gtk.ProgressBar) {
	for i, path := range *apks {
		fmt.Println(path)

		/* do the work */

		progress_bar.SetFraction(float64(1) / float64(len(*apks)) * float64(i+1))
		for gtk.EventsPending() {
			gtk.MainIteration()
		}
	}
}
