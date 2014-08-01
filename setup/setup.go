package setup

import (
	"fmt"
	"github.com/AndroSOM/FeatureMiner/helper"
	"github.com/mattn/go-gtk/gtk"
	"log"
	"os"
	"os/exec"
)

func SetupAndroguard(frame *gtk.Frame) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	update_labels := func(button *gtk.Button) {
		button.SetSensitive(true)
		if helper.FolderExists(wd+"/tools/androguard/", "") {
			button.SetLabel("remove Androguard..")
		} else {
			button.SetLabel("download and build Androguard..")
		}
	}

	button := gtk.NewButton()
	update_labels(button)

	button.Connect("clicked", func() {
		if helper.FolderExists(wd+"/tools/androguard/", "") {
			if err := os.RemoveAll(wd + "/tools/androguard/"); err != nil {
				log.Println(err)
			}
		} else {
			cmd := exec.Command(wd + "/scripts/install_androguard.sh")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Println(err)
			}
		}
		update_labels(button)
	})

	frame.Add(button)
}

func SetupOther(vbox *gtk.VBox) {
	button := gtk.NewButtonWithLabel("some depentency..")
	button.SetSensitive(false)
	vbox.Add(helper.AddButtonWithHBox(button))
}
