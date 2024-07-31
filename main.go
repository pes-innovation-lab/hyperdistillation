package main

import (
	"flag"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/data"
	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/gadgets"
	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
)

func main() {
	graphFlag := flag.Bool("graph", false, "Specify whether to enable graphing")
	traceTcpFlag := flag.Bool("trace", false, "Specify whether to start tracing tcp connections")
	filterContainerByName := flag.String("filter-name", "", "Specify names of containers delimited by ' '")
	filterContainerByRegex := flag.String("filter-regex", "", "Specify regex to filter containers")
	eventLog := flag.String("log-path", data.DefaultFileName, "")

	flag.Parse()

	var events []*graph.MetaEvent
	var filteredEvents []*graph.MetaEvent

	anyFilterOrGraph := *filterContainerByName != "" || *filterContainerByRegex != "" || *graphFlag
	anyFilter := *filterContainerByName != "" || *filterContainerByRegex != ""

	if *traceTcpFlag {
		gadgets.TraceTcp()
	}

	if anyFilterOrGraph {
		data.UnMarshalJsonEvents(*eventLog, &events)
	}

	if *filterContainerByName != "" {
		data.FilterContainerNames(&events, &filteredEvents, *filterContainerByName, *eventLog)
	}

	if *filterContainerByRegex != "" {
		data.FilterContainerNamesRegex(&events, &filteredEvents, *filterContainerByRegex, *eventLog)
	}

	if *graphFlag {
		if anyFilter {
			graph.GenerateGraph(filteredEvents)
		} else {
			graph.GenerateGraph(events)
		}

	}
}
