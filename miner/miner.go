package miner

import (
	"fmt"
	"github.com/mattn/go-gtk/gtk"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
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

func Analysis(apks *[]string, progressBar *gtk.ProgressBar, script string, numCPU int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan string, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			jobsChan <- path
		}
	}()

	for i := 0; i < numCPU; i++ {
		go AnalysisConsumer(jobsChan, doneChan, script)
	}

	jobsDone := 0
	for {
		select {
		case <-doneChan:
			jobsDone++
			progressBar.SetFraction(float64(1) / float64(numOfJobs) * float64(jobsDone))
			progressBar.SetText(strconv.Itoa(jobsDone) + "/" + strconv.Itoa(numOfJobs) + " done")
		default:
			gtk.MainIteration()
		}
		if jobsDone == numOfJobs {
			progressBar.SetFraction(0.0)
			progressBar.SetText("all done")
			break
		}
	}
}

func AnalysisConsumer(jobsChan chan string, doneChan chan int, script string) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	for {
		path := <-jobsChan
		cmd := exec.Command(wd+"/scripts/"+script, "-i"+path, "-o"+wd+"/features")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}
		doneChan <- 1
	}
}
