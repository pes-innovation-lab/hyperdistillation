package graph

import (
	"fmt"
	"os"

	// "strconv"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	// "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

type MetaEvent struct {
	Type             string
	SrcIp            string
	DstIp            string
	SrcContainerName string
	DstContainerName string
}

// Contains information about one node in the graph
type graphNode struct {
	ip            string
	containerName string
}

// Enum to denote IP type as source or destination
type srcOrDst int

const (
	src srcOrDst = iota + 1
	dst
)

func GenerateGraph(events []*MetaEvent) {
	fmt.Printf("STARTING GRAPH GENERATION\n")

	nodeHash := func(nodeInfo string) string {
		return nodeInfo
	}

	// Initialise graph
	g := graph.New(nodeHash, graph.Directed(), graph.Acyclic())

	// Create a hashmap to keep track of all nodes in the graph
	nodeMap := make(map[string]graphNode)

	for _, event := range events {
		// Ignoring TCP "close events"
		if event.Type == "close" || event.Type == "accept" {
			continue
		}

		// If the ip is already a node then don't add another node
		_, ok := nodeMap[event.SrcContainerName]
		if !ok {
			// create node in the graph
			err := g.AddVertex(event.SrcContainerName)
			if err != nil {
				panic(err)
			}

			// Add node in out map
			nodeMap[event.SrcContainerName] = graphNode{
				ip:            event.SrcIp,
				containerName: event.SrcContainerName,
			}
		}
		_, ok = nodeMap[event.DstContainerName]
		if !ok {
			// create node in the graph
			err := g.AddVertex(event.DstContainerName)
			if err != nil {
				panic(err)
			}

			// Add node in out map
			nodeMap[event.DstContainerName] = graphNode{
				ip:            event.DstIp,
				containerName: event.DstContainerName,
			}
		}

		err := g.AddEdge(event.SrcContainerName, event.DstContainerName)
		if err != nil {
			fmt.Printf("Unable to create edge from %s to %s\n", event.SrcContainerName, event.DstContainerName)
		}
		fmt.Printf("Trying to make edge from %s to %s\n", event.SrcContainerName, event.DstContainerName)
	}

	file, err := os.Create("./graph.gv")
	if err != nil {
		panic(err)
	}

	err = draw.DOT(g, file)
	if err != nil {
		panic(err)
	}
}

// func getIp(event *types.Event, srcOrDst srcOrDst) string {
// 	if srcOrDst == src {
// 		return event.SrcEndpoint.L3Endpoint.Addr
// 	} else {
// 		return event.DstEndpoint.L3Endpoint.Addr
// 	}
// }

// func appendPorts(event *types.Event, srcIp string, dstIp string) (string, string) {
// 	if !(srcIp == dstIp) {
// 		return srcIp, dstIp
// 	}

// 	appSrcIp := srcIp + ":" + strconv.FormatUint(uint64(event.SrcEndpoint.Port), 10)
// 	appDstIp := dstIp + ":" + strconv.FormatUint(uint64(event.DstEndpoint.Port), 10)

// 	return appSrcIp, appDstIp
// }
