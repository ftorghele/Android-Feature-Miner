package helper

import (
	"fmt"
	"github.com/mattn/go-gtk/gtk"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

func Authors() []string {
	if b, err := exec.Command("git", "log").Output(); err == nil {
		lines := strings.Split(string(b), "\n")

		var a []string
		r := regexp.MustCompile(`^Author:\s*([^ <]+).*$`)
		for _, e := range lines {
			ms := r.FindStringSubmatch(e)
			if ms == nil {
				continue
			}
			a = append(a, ms[1])
		}
		sort.Strings(a)
		var p string
		lines = []string{}
		for _, e := range a {
			if p == e {
				continue
			}
			lines = append(lines, e)
			p = e
		}
		return lines
	}
	return []string{"Franz Torghele <f.torghele@gmail.com>"}
}

func DisplayDialog(msg string) {
	dialog := gtk.NewMessageDialog(
		gtk.NewWindow(gtk.WINDOW_TOPLEVEL),
		gtk.DIALOG_MODAL,
		gtk.MESSAGE_INFO,
		gtk.BUTTONS_OK,
		msg)
	dialog.Run()
	dialog.Destroy()
}

func FolderExists(dir string, error_msg string) bool {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if error_msg != "" {
				DisplayDialog(error_msg)
			}
			return false
		} else {
			// other error
			fmt.Println(err)
		}
	}
	return true
}

func SetFolder(context string, dir *string) *gtk.HBox {
	hbox := gtk.NewHBox(false, 5)
	hbox.SetBorderWidth(5)

	input_box := gtk.NewEntry()
	input_box.SetText("Select " + context + " Folder..")
	input_box.SetSizeRequest(420, -1)
	input_button := gtk.NewButtonWithLabel(context + " Folder")
	input_button.SetSizeRequest(150, 0)
	input_button.Connect("clicked", func() {
		filechooserdialog := gtk.NewFileChooserDialog(
			"Choose "+context+" Folder...",
			input_button.GetTopLevelAsWindow(),
			gtk.FILE_CHOOSER_ACTION_SELECT_FOLDER,
			gtk.STOCK_OK,
			gtk.RESPONSE_ACCEPT)
		filechooserdialog.Response(func() {
			*dir = filechooserdialog.GetFilename()
			input_box.SetText(*dir)
			filechooserdialog.Destroy()
		})
		filechooserdialog.Run()
	})
	hbox.PackStart(input_button, false, false, 0)
	hbox.PackStart(input_box, false, false, 0)
	return hbox
}
