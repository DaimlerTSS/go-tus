package main

import (
	"flag"
	"fmt"
	"github.com/eventials/go-tus"
	"os"
)

const metaDataKeyFileName = "filename"

func main() {
	var file string
	flag.StringVar(&file, "file", "hello_world.txt", "file to upload")
	var url string
	flag.StringVar(&url, "url", "https://example.com", "TUS upload server URL")
	flag.Parse()

	fmt.Printf("Start uploading file '%s' to '%s'\n", file, url)

	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// create the tus client config.
	config := tus.DefaultConfig()
	config.EnforceHttps = true
	config.ChecksumAlgorithm = tus.SHA256_HEX
	config.ChunkSize = 5 * 1024 * 1024

	// create the tus client.
	client, err := tus.NewClient(url, config)
	if err != nil {
		panic(err)
	}

	// create an upload from a file.
	upload, err := tus.NewUploadFromFile(f)
	if err != nil {
		panic(err)
	}

	// create or resume the uploader.
	uploader, err := client.StartOrResumeUploadFromServer(upload)
	if err != nil {
		panic(err)
	}

	c := make(chan tus.Upload)
	uploader.NotifyUploadProgress(c)
	go func() {
		for {
			res := <-c
			fmt.Printf("Progress: %3d%% offset: %d %v\n", res.Progress(), res.Offset(), res.Metadata[metaDataKeyFileName])
			if res.Finished() {
				return
			}
		}
	}()

	// start the uploading process.
	if err = uploader.Upload(); err != nil {
		panic(err)
	}

	fmt.Println("Upload finished")
}
