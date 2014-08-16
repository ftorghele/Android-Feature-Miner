package setup

import (
	"github.com/mattn/go-gtk/gtk"
	"log"
	"os"
	"os/exec"
)

var working_dir string

func init() {
	wd, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	working_dir = wd
}

func setup(vbox *gtk.VBox, label string, script string) *gtk.Button {
	button := gtk.NewButtonWithLabel(label)

	button.Connect("clicked", func() {
		vbox.SetSensitive(false)
		gtk.MainIteration()

		doneChan := make(chan bool)
		go func() {
			cmd := exec.Command(working_dir + script)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Println(err)
			}
			doneChan <- true
		}()

		for {
			select {
			case <-doneChan:
				vbox.SetSensitive(true)
			default:
				gtk.MainIteration()
			}
			if vbox.IsSensitive() {
				break
			}
		}
	})

	return button
}

func StaticAnalysis(frame *gtk.Frame, vbox *gtk.VBox) {
	frame.Add(setup(vbox, "(Re)Install Androguard", "/scripts/setup/androguard.sh"))
}

func DynamicAnalysis(frame *gtk.Frame, vbox *gtk.VBox) {
	buttonVbox := gtk.NewVBox(false, 1)
	buttonVbox.PackStart(setup(vbox, "(Re)Install Dependencies", "/scripts/setup/dependencies.sh"), true, true, 5)
	buttonVbox.PackStart(setup(vbox, "(Re)Install Android", "/scripts/setup/android.sh"), true, true, 5)
	buttonVbox.PackStart(setup(vbox, "(Re)Install Virtualbox", "/scripts/setup/virtualbox.sh"), true, true, 5)
	buttonVbox.PackStart(setup(vbox, "(Re)Download Android x86 VM", "/scripts/setup/download_vm.sh"), true, true, 5)

	prepareHbox := gtk.NewHBox(false, 10)
	prepareHbox.PackStart(setup(vbox, "(Re)Import and start VM", "/scripts/setup/import_vm.sh"), true, true, 5)
	prepareHbox.PackStart(gtk.NewLabel("1. Wait until VM has fully started.\n2. Unlock the screen.\n3. Take the \"cleanstate\" Snapshot."), true, true, 5)
	prepareHbox.PackStart(setup(vbox, "Take Snapshot", "/scripts/setup/snapshot_vm.sh"), true, true, 5)

	buttonVbox.PackStart(prepareHbox, true, true, 5)
	frame.Add(buttonVbox)
}
