package main

import (
	"fmt"
	"github.com/AndroSOM/FeatureMiner/miner"
	"github.com/AndroSOM/FeatureMiner/setup"
	"github.com/mattn/go-gtk/gtk"
	"gopkg.in/mgo.v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
)

var working_dir string
var input_folder, output_folder string
var apks []string

func createWindow() *gtk.Window {
	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetTitle("AndroSOM Feature Miner")
	window.SetDefaultSize(600, 600)
	vbox := gtk.NewVBox(false, 1)
	createMenu(window, vbox)

	notebook := gtk.NewNotebook()
	main_page := gtk.NewFrame("Miner")
	main_page.Add(minerPage())
	notebook.AppendPage(main_page, gtk.NewLabel("Feature Miner"))
	build_dataset_page := gtk.NewFrame("Build Dataset")
	build_dataset_page.Add(buildDatasetPage())
	notebook.AppendPage(build_dataset_page, gtk.NewLabel("Build Dataset"))
	setup_page := gtk.NewFrame("Setup")
	setup_page.Add(setupPage())
	notebook.AppendPage(setup_page, gtk.NewLabel("Dependencies"))

	vbox.Add(notebook)
	window.Add(vbox)
	return window
}

func createMenu(w *gtk.Window, vbox *gtk.VBox) {
	action_group := gtk.NewActionGroup("my_group")
	ui_info := `
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
	ui_manager.AddUIFromString(ui_info)
	accel_group := ui_manager.GetAccelGroup()
	w.AddAccelGroup(accel_group)

	action_group.AddAction(gtk.NewAction("FileMenu", "File", "", ""))

	action_filequit := gtk.NewAction("FileQuit", "", "", gtk.STOCK_QUIT)
	action_filequit.Connect("activate", gtk.MainQuit)
	action_group.AddActionWithAccel(action_filequit, "")

	action_group.AddAction(gtk.NewAction("HelpMenu", "Help", "", ""))

	action_help_about := gtk.NewAction("HelpAbout", "About", "", "")
	action_help_about.Connect("activate", func() {
		dialog := gtk.NewAboutDialog()
		dialog.SetProgramName("FeatureMiner")
		dialog.SetComments("FeatureMiner is part of the AndroSOM project which was built at the university of applied sciences Salzburg as part of a master's thesis.")
		dialog.SetAuthors([]string{"Franz Torghele <f.torghele@gmail.com>"})
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

func minerPage() *gtk.VBox {
	vbox := gtk.NewVBox(false, 1)

	general_analysis_frame := gtk.NewVBox(false, 1)

	general_analysis_frame.Add(setFolder("Input", &input_folder))
	general_analysis_frame.Add(setFolder("Output", &output_folder))

	load_button_hbox := gtk.NewHBox(false, 0)
	load_button_hbox.SetBorderWidth(5)
	load_button_hbox.SetSizeRequest(-1, 60)
	load_button := gtk.NewButtonWithLabel("Load Android APKs")
	load_button_hbox.PackStart(load_button, true, true, 0)
	general_analysis_frame.Add(load_button_hbox)

	apk_count_label_hbox := gtk.NewHBox(false, 0)
	apk_count_label_hbox.SetBorderWidth(5)
	apk_count_label_hbox.SetSizeRequest(-1, 30)
	apk_count_label := gtk.NewLabel("Loaded APKs: None.. Please load APKs to continue.")
	apk_count_label_hbox.PackStart(apk_count_label, true, true, 0)
	general_analysis_frame.Add(apk_count_label_hbox)

	vbox.PackStart(general_analysis_frame, false, true, 0)

	/* VirusTotal Analysis */

	vt_analysis_frame := gtk.NewFrame("1. VirusTotal")
	vt_analysis_frame.SetBorderWidth(5)
	vt_analysis_frame.SetSensitive(false)

	vt_analysis_vbox := gtk.NewVBox(false, 0)

	vt_analysis_hbox1 := gtk.NewHBox(false, 0)
	vt_analysis_hbox1.SetBorderWidth(10)
	vt_analysis_hbox1.SetSizeRequest(-1, 60)

	vt_analysis_progress := gtk.NewProgressBar()
	vt_analysis_start_button := gtk.NewButtonWithLabel("Start Analysis")
	vt_analysis_cpu_count := gtk.NewSpinButtonWithRange(1, float64(runtime.NumCPU()), 1)
	vt_analysis_cpu_count_label := gtk.NewLabel("CPUs: ")
	vt_analysis_cpu_count.Spin(gtk.SPIN_USER_DEFINED, float64(runtime.NumCPU()))
	vt_analysis_cpu_count.SetSizeRequest(40, -1)

	vt_analysis_hbox1.PackStart(vt_analysis_start_button, false, true, 5)
	vt_analysis_hbox1.PackStart(vt_analysis_progress, true, true, 5)
	vt_analysis_hbox1.PackStart(vt_analysis_cpu_count_label, false, true, 5)
	vt_analysis_hbox1.PackStart(vt_analysis_cpu_count, false, true, 5)

	vt_analysis_hbox2 := gtk.NewHBox(false, 0)
	vt_analysis_hbox2.SetBorderWidth(10)
	vt_analysis_hbox2.SetSizeRequest(-1, 60)

	vt_analysis_api_label := gtk.NewLabel("VirusTotal API Key: ")
	vt_analysis_api_key := gtk.NewEntry()

	vt_analysis_api_type := gtk.NewComboBoxText()
	vt_analysis_api_type.AppendText("public API Key")
	vt_analysis_api_type.AppendText("private API Key")
	vt_analysis_api_type.SetActive(0)

	vt_analysis_hbox2.PackStart(vt_analysis_api_label, false, false, 5)
	vt_analysis_hbox2.PackStart(vt_analysis_api_key, true, true, 5)
	vt_analysis_hbox2.PackStart(vt_analysis_api_type, false, false, 5)

	vt_analysis_vbox.Add(vt_analysis_hbox1)
	vt_analysis_vbox.Add(vt_analysis_hbox2)
	vt_analysis_vbox.PackStart(gtk.NewLabel("With a public Key only 4 requests/minute are possible."), false, false, 5)
	vt_analysis_frame.Add(vt_analysis_vbox)
	vbox.PackStart(vt_analysis_frame, false, true, 0)

	/* Static Analysis */

	static_analysis_frame := gtk.NewFrame("2. Static Analysis")
	static_analysis_frame.SetBorderWidth(5)
	static_analysis_frame.SetSensitive(false)

	static_analysis_hbox := gtk.NewHBox(false, 0)
	static_analysis_hbox.SetBorderWidth(10)
	static_analysis_hbox.SetSizeRequest(-1, 60)

	static_analysis_progress := gtk.NewProgressBar()
	static_analysis_start_button := gtk.NewButtonWithLabel("Start Analysis")

	static_analysis_cpu_count := gtk.NewSpinButtonWithRange(1, float64(runtime.NumCPU()), 1)
	static_analysis_cpu_count_label := gtk.NewLabel("CPUs: ")
	static_analysis_cpu_count.Spin(gtk.SPIN_USER_DEFINED, float64(runtime.NumCPU()))
	static_analysis_cpu_count.SetSizeRequest(40, -1)

	static_analysis_hbox.PackStart(static_analysis_start_button, false, true, 5)
	static_analysis_hbox.PackStart(static_analysis_progress, true, true, 5)
	static_analysis_hbox.PackStart(static_analysis_cpu_count_label, false, true, 5)
	static_analysis_hbox.PackStart(static_analysis_cpu_count, false, true, 5)
	static_analysis_frame.Add(static_analysis_hbox)
	vbox.PackStart(static_analysis_frame, false, true, 0)

	/* Dynamic Analysis */

	dynamic_analysis_frame := gtk.NewFrame("3. Dynamic Analysis")
	dynamic_analysis_frame.SetBorderWidth(5)
	dynamic_analysis_frame.SetSensitive(false)

	dynamic_analysis_hbox := gtk.NewHBox(false, 0)
	dynamic_analysis_hbox.SetBorderWidth(10)
	dynamic_analysis_hbox.SetSizeRequest(-1, 60)

	dynamic_analysis_progress := gtk.NewProgressBar()
	dynamic_analysis_start_button := gtk.NewButtonWithLabel("Start Analysis")

	dynamic_analysis_hbox.PackStart(dynamic_analysis_start_button, false, true, 5)
	dynamic_analysis_hbox.PackStart(dynamic_analysis_progress, true, true, 5)
	dynamic_analysis_frame.Add(dynamic_analysis_hbox)
	vbox.PackStart(dynamic_analysis_frame, false, true, 0)

	/* Helpers */

	disable_gui := func() {
		general_analysis_frame.SetSensitive(false)
		static_analysis_frame.SetSensitive(false)
		dynamic_analysis_frame.SetSensitive(false)
		vt_analysis_frame.SetSensitive(false)
	}

	enable_gui := func() {
		general_analysis_frame.SetSensitive(true)
		static_analysis_frame.SetSensitive(true)
		dynamic_analysis_frame.SetSensitive(true)
		vt_analysis_frame.SetSensitive(true)
	}

	/* Events */

	load_button.Connect("clicked", func() {
		if folderExists(input_folder, "Please provide a valid input directory!") && folderExists(output_folder, "Please provide a valid output directory!") {
			miner.LoadAPKs(input_folder, &apks, load_button)
			if len(apks) > 0 {
				apk_count_label.SetLabel("Loaded APKs: " + strconv.Itoa(len(apks)))
				enable_gui()
			} else {
				apk_count_label.SetLabel("No APKs found in this input folder..")
				disable_gui()
				general_analysis_frame.SetSensitive(true)
			}
		}
	})

	static_analysis_start_button.Connect("clicked", func() {
		session, err := mgo.Dial("localhost:6662")
		if err != nil {
			panic(err)
		}
		defer session.Close()
		session.SetMode(mgo.Monotonic, true)

		db := session.DB("androsom")
		if count, _ := db.C("virustotal_features").Count(); count == 0 {
			displayDialog("get VirusTotal metadata first.")
			return
		}

		fmt.Println("starting static analysis..")
		disable_gui()
		miner.Analysis(&apks, static_analysis_progress, output_folder, "static_analysis.py", static_analysis_cpu_count.GetValueAsInt())
		enable_gui()
	})

	dynamic_analysis_start_button.Connect("clicked", func() {
		session, err := mgo.Dial("localhost:6662")
		if err != nil {
			panic(err)
		}
		defer session.Close()
		session.SetMode(mgo.Monotonic, true)

		db := session.DB("androsom")
		if count, _ := db.C("static_features").Count(); count == 0 {
			displayDialog("run static analysis first.")
			return
		}
		if count, _ := db.C("virustotal_features").Count(); count == 0 {
			displayDialog("get VirusTotal metadata first.")
			return
		}

		fmt.Println("starting dynamic analysis..")
		disable_gui()
		miner.Analysis(&apks, dynamic_analysis_progress, output_folder, "dynamic_analysis.py", 1)
		enable_gui()
	})

	vt_analysis_start_button.Connect("clicked", func() {
		api_key := vt_analysis_api_key.GetText()
		api_type := vt_analysis_api_type.GetActiveText()
		api_request_pause_ms := 25000
		api_request_cpu_count := 1
		if api_type == "private API Key" {
			api_request_pause_ms = 100
			api_request_cpu_count = vt_analysis_cpu_count.GetValueAsInt()
		}
		if len(api_key) != 64 {
			displayDialog("Please enter a valid VirusTotal API Key.")
		} else {
			fmt.Println("getting metatada from VirusTotal..")
			disable_gui()
			miner.VirusTotal(&apks, vt_analysis_progress, api_key, api_request_pause_ms, api_request_cpu_count)
			enable_gui()
		}
	})

	return vbox
}

func buildDatasetPage() *gtk.VBox {
	vbox := gtk.NewVBox(false, 1)

	/* Prepare Build Datasets */

	prepare_frame := gtk.NewFrame("Preparation")
	prepare_frame.SetBorderWidth(5)

	prepare_hbox := gtk.NewHBox(false, 0)
	prepare_hbox.SetBorderWidth(10)
	prepare_hbox.SetSizeRequest(-1, 60)

	prepare_progress := gtk.NewProgressBar()
	prepare_start_button := gtk.NewButtonWithLabel("   Run   ")

	prepare_cpu_count := gtk.NewSpinButtonWithRange(1, float64(runtime.NumCPU()), 1)
	prepare_cpu_count_label := gtk.NewLabel("CPUs: ")
	prepare_cpu_count.Spin(gtk.SPIN_USER_DEFINED, float64(runtime.NumCPU()))
	prepare_cpu_count.SetSizeRequest(40, -1)

	prepare_hbox.PackStart(prepare_start_button, false, true, 5)
	prepare_hbox.PackStart(prepare_progress, true, true, 5)
	prepare_hbox.PackStart(prepare_cpu_count_label, false, true, 5)
	prepare_hbox.PackStart(prepare_cpu_count, false, true, 5)
	prepare_frame.Add(prepare_hbox)
	vbox.PackStart(prepare_frame, false, true, 0)

	/* Build Datasets */

	build_datasets_frame := gtk.NewFrame("Build Datasets")
	build_datasets_frame.SetBorderWidth(5)

	build_datasets_vbox := gtk.NewVBox(false, 0)

	build_datasets_hbox1 := gtk.NewHBox(false, 0)
	build_datasets_hbox1.SetBorderWidth(10)
	build_datasets_hbox1.SetSizeRequest(-1, 60)

	build_datasets_progress := gtk.NewProgressBar()
	build_datasets_start_button := gtk.NewButtonWithLabel("   Run   ")

	build_datasets_cpu_count := gtk.NewSpinButtonWithRange(1, float64(runtime.NumCPU()), 1)
	build_datasets_cpu_count_label := gtk.NewLabel("CPUs: ")
	build_datasets_cpu_count.Spin(gtk.SPIN_USER_DEFINED, float64(runtime.NumCPU()))
	build_datasets_cpu_count.SetSizeRequest(40, -1)

	build_datasets_hbox1.PackStart(build_datasets_start_button, false, true, 5)
	build_datasets_hbox1.PackStart(build_datasets_progress, true, true, 5)
	build_datasets_hbox1.PackStart(build_datasets_cpu_count_label, false, true, 5)
	build_datasets_hbox1.PackStart(build_datasets_cpu_count, false, true, 5)

	build_datasets_hbox2 := gtk.NewHBox(false, 0)
	build_datasets_hbox2.SetBorderWidth(10)
	build_datasets_hbox2.SetSizeRequest(-1, 60)

	build_datasets_static_filter := gtk.NewSpinButtonWithRange(1, 99999, 1)
	build_datasets_static_filter_label := gtk.NewLabel("static Filter: ")
	build_datasets_static_filter.Spin(gtk.SPIN_USER_DEFINED, 49)
	build_datasets_static_filter.SetSizeRequest(40, -1)
	build_datasets_hbox2.PackStart(build_datasets_static_filter_label, true, true, 5)
	build_datasets_hbox2.PackStart(build_datasets_static_filter, false, true, 5)

	build_datasets_dynamic_filter := gtk.NewSpinButtonWithRange(1, 99999, 1)
	build_datasets_dynamic_filter_label := gtk.NewLabel("dynamic Filter: ")
	build_datasets_dynamic_filter.Spin(gtk.SPIN_USER_DEFINED, 49)
	build_datasets_dynamic_filter.SetSizeRequest(40, -1)
	build_datasets_hbox2.PackStart(build_datasets_dynamic_filter_label, true, true, 5)
	build_datasets_hbox2.PackStart(build_datasets_dynamic_filter, false, true, 5)

	build_datasets_traffic_filter := gtk.NewSpinButtonWithRange(1, 99999, 1)
	build_datasets_traffic_filter_label := gtk.NewLabel("traffic Filter: ")
	build_datasets_traffic_filter.Spin(gtk.SPIN_USER_DEFINED, 49)
	build_datasets_traffic_filter.SetSizeRequest(40, -1)
	build_datasets_hbox2.PackStart(build_datasets_traffic_filter_label, true, true, 5)
	build_datasets_hbox2.PackStart(build_datasets_traffic_filter, false, true, 5)

	build_datasets_vbox.Add(build_datasets_hbox2)
	build_datasets_vbox.Add(build_datasets_hbox1)
	build_datasets_frame.Add(build_datasets_vbox)
	vbox.PackStart(build_datasets_frame, false, true, 0)

	/* Helpers */

	disable_gui := func() {
		prepare_frame.SetSensitive(false)
		build_datasets_frame.SetSensitive(false)
	}

	enable_gui := func() {
		prepare_frame.SetSensitive(true)
		build_datasets_frame.SetSensitive(true)
	}

	/* Events */

	prepare_start_button.Connect("clicked", func() {
		session, err := mgo.Dial("localhost:6662")
		if err != nil {
			panic(err)
		}
		defer session.Close()
		session.SetMode(mgo.Monotonic, true)

		db := session.DB("androsom")
		if count, _ := db.C("static_features").Count(); count == 0 {
			displayDialog("run static analysis first.")
			return
		}
		if count, _ := db.C("dynamic_features").Count(); count == 0 {
			displayDialog("run dynamic analysis first.")
			return
		}
		if count, _ := db.C("virustotal_features").Count(); count == 0 {
			displayDialog("get VirusTotal metadata first.")
			return
		}

		if len(apks) == 0 {
			displayDialog("load APKs first (Feature Miner Tab).")
			return
		}

		db.C("features").DropCollection()

		fmt.Println("preperation for building datasets..")
		disable_gui()
		miner.Analysis(&apks, prepare_progress, output_folder, "build_feature_vector_prepare.py", prepare_cpu_count.GetValueAsInt())
		enable_gui()
	})

	build_datasets_start_button.Connect("clicked", func() {
		session, err := mgo.Dial("localhost:6662")
		if err != nil {
			panic(err)
		}
		defer session.Close()
		session.SetMode(mgo.Monotonic, true)

		db := session.DB("androsom")
		if count, _ := db.C("features").Count(); count == 0 {
			displayDialog("run preperation first.")
			return
		}

		if len(apks) == 0 {
			displayDialog("load APKs first (Feature Miner Tab).")
			return
		}
		if output_folder == "" {
			displayDialog("set output folder first (Feature Miner Tab).")
			return
		}

		fmt.Println("building datasets..")
		disable_gui()

		// clear old features
		d, err := os.Open(working_dir + "/tmp/")
		if err != nil {
			fmt.Println(err)
		}
		defer d.Close()

		files, err := d.Readdir(-1)
		if err != nil {
			fmt.Println(err)
		}

		for _, file := range files {
			if file.Mode().IsRegular() {
				if filepath.Ext(file.Name()) == ".features" {
					os.Remove(working_dir + "/tmp/" + file.Name())
					fmt.Println("Deleted ", file.Name())
				}
			}
		}

		// build feature vectors
		miner.ExtractFeatures(&apks, build_datasets_progress, output_folder, build_datasets_cpu_count.GetValueAsInt(), build_datasets_static_filter.GetValueAsInt(), build_datasets_dynamic_filter.GetValueAsInt(), build_datasets_traffic_filter.GetValueAsInt())

		// build Datasets
		cmd := exec.Command(working_dir+"/scripts/build_datasets.py", "-o", output_folder)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}

		enable_gui()
	})

	return vbox
}

func setupPage() *gtk.VBox {
	vbox := gtk.NewVBox(false, 1)

	static_analysis_frame := gtk.NewFrame("Static Analysis")
	static_analysis_frame.SetBorderWidth(5)
	setup.StaticAnalysis(static_analysis_frame, vbox)

	dynamic_analysis_frame := gtk.NewFrame("Dynamic Analysis")
	dynamic_analysis_frame.SetBorderWidth(5)
	setup.DynamicAnalysis(dynamic_analysis_frame, vbox)

	vbox.Add(static_analysis_frame)
	vbox.Add(dynamic_analysis_frame)
	return vbox
}

func startMongoDB() {
	if folderExists(working_dir+"/tools/mongodb/bin/mongod", "Install all dependencies before mining!") {
		fmt.Println("Starting MongoDB..")
		cmd := exec.Command(working_dir+"/tools/mongodb/bin/mongod", "--dbpath", working_dir+"/data", "--noauth", "--port", "6662")
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
		}
	}
}

func stopMongoDB() {
	_, err := exec.Command("pgrep", "mongod").Output()
	if err == nil {
		fmt.Println("Stopping MongoDB..")
		cmd := exec.Command(working_dir+"/tools/mongodb/bin/mongod", "--shutdown", "--dbpath", working_dir+"/data")
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
		}
	}
}

func displayDialog(msg string) {
	dialog := gtk.NewMessageDialog(
		gtk.NewWindow(gtk.WINDOW_TOPLEVEL),
		gtk.DIALOG_MODAL,
		gtk.MESSAGE_INFO,
		gtk.BUTTONS_OK,
		msg)
	dialog.Run()
	dialog.Destroy()
}

func folderExists(dir string, error_msg string) bool {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if error_msg != "" {
				displayDialog(error_msg)
			}
			return false
		} else {
			// other error
			fmt.Println(err)
		}
	}
	return true
}

func setFolder(context string, dir *string) *gtk.HBox {
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

func main() {
	gtk.Init(nil)
	window := createWindow()
	startMongoDB()
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.Connect("destroy", func() {
		stopMongoDB()
		fmt.Println("bye")
		gtk.MainQuit()
	})
	window.ShowAll()
	gtk.Main()
}

func init() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	working_dir = wd
}
