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

type Job struct {
	command string
	args    []string
}

func Analysis(apks *[]string, progressBar *gtk.ProgressBar, outputFolder string, script string, numCPU int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan Job, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			args := []string{
				"-i" + path,
				"-o" + outputFolder,
			}
			job := Job{command: working_dir + "/scripts/" + script, args: args}
			jobsChan <- job
		}
	}()

	for i := 0; i < numCPU; i++ {
		go consumer(jobsChan, doneChan)
	}

	updateGui(doneChan, progressBar, numOfJobs)
}

func VirusTotal(apks *[]string, progressBar *gtk.ProgressBar, apiKey string, delay int, numCPU int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan Job, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			args := []string{
				"-i" + path,
				"-k" + apiKey,
				"-d" + strconv.Itoa(delay),
			}
			job := Job{command: working_dir + "/scripts/virus_total.py", args: args}
			jobsChan <- job
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}()

	for i := 0; i < numCPU; i++ {
		go consumer(jobsChan, doneChan)
	}

	updateGui(doneChan, progressBar, numOfJobs)
}

func ExtractFeatures(apks *[]string, progressBar *gtk.ProgressBar, outputFolder string, numCPU int, staticFilter int, dynamicFilter int, trafficFilter int) {
	numOfJobs := len(*apks)
	jobsChan := make(chan Job, numOfJobs)
	doneChan := make(chan int)

	go func() {
		for _, path := range *apks {
			args := []string{
				"-i" + path,
				"-o" + outputFolder,
				"-s" + strconv.Itoa(staticFilter),
				"-d" + strconv.Itoa(dynamicFilter),
				"-t" + strconv.Itoa(trafficFilter),
			}
			job := Job{command: working_dir + "/scripts/build_feature_vector.py", args: args}
			jobsChan <- job
		}
	}()

	for i := 0; i < numCPU; i++ {
		go consumer(jobsChan, doneChan)
	}

	updateGui(doneChan, progressBar, numOfJobs)
}

func updateGui(doneChan chan int, progressBar *gtk.ProgressBar, numOfJobs int) {
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

func consumer(jobsChan chan Job, doneChan chan int) {
	for {
		job := <-jobsChan
		cmd := exec.Command(job.command, job.args...)
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
