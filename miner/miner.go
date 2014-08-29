package miner

import (
	"fmt"
	"github.com/mattn/go-gtk/gtk"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

var working_dir string

func LoadAPKs(inputDir string, apks *[]string, button *gtk.Button) {
	*apks = nil
	filepath.Walk(inputDir, func(filePath string, _ os.FileInfo, _ error) error {
		if path.Ext(filePath) == ".apk" || path.Ext(filePath) == ".APK" {
			*apks = append(*apks, filePath)
		}
		return nil
	})
}

func Analysis(apks *[]string, progressBar *gtk.ProgressBar, outputFolder string, script string, numCPU int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan string, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			jobsChan <- path
		}
	}()

	for i := 0; i < numCPU; i++ {
		go analysisConsumer(jobsChan, doneChan, outputFolder, script)
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

func analysisConsumer(jobsChan chan string, doneChan chan int, outputFolder string, script string) {
	for {
		input := <-jobsChan
		cmd := exec.Command(working_dir+"/scripts/"+script, "-i", input, "-o", outputFolder)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}
		doneChan <- 1
	}
}

func VirusTotal(apks *[]string, progressBar *gtk.ProgressBar, apiKey string, delay int, numCPU int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan string, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			jobsChan <- path
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}()

	for i := 0; i < numCPU; i++ {
		go virusTotalConsumer(jobsChan, doneChan, apiKey, delay)
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

func virusTotalConsumer(jobsChan chan string, doneChan chan int, apiKey string, delay int) {
	for {
		input := <-jobsChan
		cmd := exec.Command(working_dir+"/scripts/virus_total.py", "-i"+input, "-k"+apiKey, "-d"+strconv.Itoa(delay))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}
		doneChan <- 1
	}
}

func init() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	working_dir = wd
}
