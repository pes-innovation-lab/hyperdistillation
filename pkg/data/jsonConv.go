package data

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
)

const (
	DefaultFileName = "./logs/events.json"
)

func MarshalMetaEvent(filename string, events []*graph.MetaEvent) {
	jsonEvents, err := json.Marshal(events)
	if err != nil {
		fmt.Printf("Marshalling error: %v\n", err)
	}

	if filename == "" {
		filename = DefaultFileName
	}

	dirPath := filepath.Dir(filename)
	if err = os.MkdirAll(dirPath, os.ModePerm); err != nil {
		fmt.Printf("error while creating subdirectory to store logs: %v\n", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
	}
	defer file.Close()

	_, err = file.Write(jsonEvents)
	if err != nil {
		fmt.Printf("Error writing json data to file: %v\n", err)
	}
}

func UnMarshalJsonEvents(filename string, events *[]*graph.MetaEvent) {
	if filename == "" {
		filename = DefaultFileName
	}

	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("Error reading file size: %v\n", err)

	}

	buffer := make([]byte, fileInfo.Size())

	_, err = file.Read(buffer)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}

	err = json.Unmarshal(buffer, events)
	if err != nil {
		fmt.Printf("Error unmarshalling file: %v\n", err)
	}
}
