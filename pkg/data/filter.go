package data

import (
	"regexp"
	"strings"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
)

func FilterContainerNames(events *[]*graph.MetaEvent, filteredEvents *[]*graph.MetaEvent, filterString string, eventLog string) {
	containerNames := strings.Split(filterString, " ")

	containerMap := make(map[string]int)
	for _, containerName := range containerNames {
		containerMap[containerName] = 1
	}

	// Do the filtering of logs based on container name
	for _, event := range *events {
		_, ok := containerMap[event.SrcContainerName]
		if ok {
			*filteredEvents = append(*filteredEvents, event)
			continue
		}
		_, ok = containerMap[event.DstContainerName]
		if ok {
			*filteredEvents = append(*filteredEvents, event)
			continue
		}
	}
}

func FilterContainerNamesRegex(events *[]*graph.MetaEvent, filteredEvents *[]*graph.MetaEvent, reString string, eventLog string) {
	re := regexp.MustCompile(reString)

	containerMap := make(map[string]int)

	for _, event := range *events {

		// containerNames := []string{event.DstContainerName, event.SrcContainerName}

		var containerNames []string
		
		if event.SrcContainerName != event.SrcIp {
				containerNames = append(containerNames, event.SrcContainerName)
		}
		if event.DstContainerName != event.DstIp {
				containerNames = append(containerNames, event.DstContainerName)
		}

		for _, containerName := range containerNames {
			_, ok := containerMap[containerName]
			if ok {
				*filteredEvents = append(*filteredEvents, event)
				continue
			}
			// Check if the regex matches
			filteredContainers := filterRegex(containerNames, re)

			if len(filteredContainers) == 0 {
				continue
			}

			for _, container := range filteredContainers {
				containerMap[container] = 1
			}
			*filteredEvents = append(*filteredEvents, event)
		}
	}

}

func filterRegex(arrayToFilter []string, re *regexp.Regexp) []string {
	var filteredStrings []string
	for _, stringToFilter := range arrayToFilter {
		if re.MatchString(stringToFilter) {
			filteredStrings = append(filteredStrings, stringToFilter)
		}
	}
	return filteredStrings
}
