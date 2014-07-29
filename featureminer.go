package main

import (
	"fmt"
	"github.com/AndroSOM/AndroSOM/helper"
	"github.com/AndroSOM/AndroSOM/miner"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"strconv"
)

var inputFolder, outputFolder string
var apks []string

func CreateWindow() *gtk.Window {
	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetTitle("AndroSOM Feature Miner")
	window.SetDefaultSize(700, 600)
	vbox := gtk.NewVBox(false, 1)
	CreateMenu(window, vbox)
	CreateMiner(vbox)
	window.Add(vbox)
	return window
}

func CreateMenu(w *gtk.Window, vbox *gtk.VBox) {
	action_group := gtk.NewActionGroup("my_group")
	ui_manager := CreateUIManager()
	accel_group := ui_manager.GetAccelGroup()
	w.AddAccelGroup(accel_group)

	action_group.AddAction(gtk.NewAction("FileMenu", "File", "", ""))

	action_filequit := gtk.NewAction("FileQuit", "", "", gtk.STOCK_QUIT)
	action_filequit.Connect("activate", func() {
		fmt.Println("Exiting FeatureMiner..")
		gtk.MainQuit()
	})
	action_group.AddActionWithAccel(action_filequit, "")

	action_group.AddAction(gtk.NewAction("HelpMenu", "Help", "", ""))

	action_help_about := gtk.NewAction("HelpAbout", "About", "", "")
	action_help_about.Connect("activate", func() {
		dialog := gtk.NewAboutDialog()
		dialog.SetProgramName("FeatureMiner")
		dialog.SetComments("FeatureMiner is part of the AndroSOM project which was built at the university of applied sciences Salzburg as part of a master's thesis.")
		dialog.SetAuthors(helper.Authors())
		dialog.SetLicense("Copyright (c) 2014 AndroSOM\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of button software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and button permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.")
		dialog.SetWrapLicense(true)
		dialog.Run()
		dialog.Destroy()
	})
	action_group.AddActionWithAccel(action_help_about, "")

	ui_manager.InsertActionGroup(action_group, 0)
	menubar := ui_manager.GetWidget("/MenuBar")
	vbox.PackStart(menubar, false, false, 0)
	eventbox := gtk.NewEventBox()
	vbox.PackStart(eventbox, false, false, 0)
}

func CreateMiner(vbox *gtk.VBox) {
	general_settings_frame := gtk.NewFrame("General")
	general_settings_frame.SetBorderWidth(5)

	framebox := gtk.NewVBox(false, 1)

	load_button := gtk.NewButtonWithLabel("Load Android APKs")
	load_button.SetSizeRequest(150, 0)

	framebox.Add(helper.SetFolder("Input", &inputFolder))
	framebox.Add(helper.SetFolder("Output", &outputFolder))
	framebox.Add(helper.AddButtonWithHBox(load_button))

	hbox := gtk.NewHBox(false, 10)
	hbox.SetBorderWidth(5)

	apk_count_label := gtk.NewLabel("Loaded APKs: None.. Please load APKs to continue.")
	hbox.Add(apk_count_label)
	framebox.Add(hbox)

	general_settings_frame.Add(framebox)
	vbox.PackStart(general_settings_frame, false, true, 0)

	static_analysis_frame := gtk.NewFrame("Static Analysis")
	static_analysis_frame.SetBorderWidth(5)
	static_analysis_frame.SetSensitive(false)

	static_analysis_start_button := gtk.NewButtonWithLabel("Start Static Analysis")
	static_analysis_start_button.SetSizeRequest(150, 0)
	static_analysis_start_button.Connect("clicked", func() {
		fmt.Println("starting static analysis..")
	})

	static_analysis_frame.Add(helper.AddButtonWithHBox(static_analysis_start_button))
	vbox.PackStart(static_analysis_frame, false, true, 0)

	dynamic_analysis_frame := gtk.NewFrame("Dynamic Analysis")
	dynamic_analysis_frame.SetBorderWidth(5)
	dynamic_analysis_frame.SetSensitive(false)

	dynamic_analysis_start_button := gtk.NewButtonWithLabel("Start Dynamic Analysis")
	dynamic_analysis_start_button.SetSizeRequest(150, 0)
	dynamic_analysis_start_button.Connect("clicked", func() {
		fmt.Println("starting dynamic analysis..")
	})

	dynamic_analysis_frame.Add(helper.AddButtonWithHBox(dynamic_analysis_start_button))
	vbox.PackStart(dynamic_analysis_frame, false, true, 0)

	load_button.Connect("clicked", func() {
		if miner.CheckFolderExists(inputFolder, "Please provide a valid input directory!") && miner.CheckFolderExists(outputFolder, "Please provide a valid output directory!") {
			miner.LoadAPKs(inputFolder, &apks, load_button)
			if len(apks) > 0 {
				apk_count_label.SetLabel("Loaded APKs: " + strconv.Itoa(len(apks)))
				static_analysis_frame.SetSensitive(true)
				dynamic_analysis_frame.SetSensitive(true)
			} else {
				apk_count_label.SetLabel("No APKs found in this input folder..")
				static_analysis_frame.SetSensitive(false)
				dynamic_analysis_frame.SetSensitive(false)
			}
		}
	})
}

func CreateUIManager() *gtk.UIManager {
	UI_INFO := `
<ui>
  <menubar name='MenuBar'>
    <menu action='FileMenu'>
      <menuitem action='FileQuit' />
    </menu>
    <menu action='HelpMenu'>
      <menuitem action='HelpAbout'/>
    </menu>
  </menubar>
</ui>
`
	ui_manager := gtk.NewUIManager()
	ui_manager.AddUIFromString(UI_INFO)
	return ui_manager
}

func main() {
	gtk.Init(nil)
	window := CreateWindow()
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.Connect("destroy", func(ctx *glib.CallbackContext) {
		fmt.Println("destroy pending...")
		gtk.MainQuit()
	}, "exit")
	window.ShowAll()
	gtk.Main()
}
