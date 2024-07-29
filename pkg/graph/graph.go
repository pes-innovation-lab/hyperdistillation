package graph

import (
	"fmt"
	"os"
	"strconv"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

// Contains information about one node in the graph
type graphNode struct {
	Event *types.Event
	ip    string
}

// Enum to denote IP type as source or destination
type srcOrDst int

const (
	src srcOrDst = iota + 1
	dst
)

func GenerateGraph(events []*types.Event) {
	fmt.Printf("STARTING GRAPH GENERATION\n")

	ipHash := func(addr string) string {
		return addr
	}

	// Initialise graph
	g := graph.New(ipHash, graph.Directed(), graph.PreventCycles())

	// Create a hashmap to keep track of all nodes in the graph
	nodeMap := make(map[string]graphNode)

	for _, event := range events {

		if event.Operation == "close" {
			continue
		}

		srcIp := getIp(event, src)
		dstIp := getIp(event, dst)

		srcIp, dstIp = appendPorts(event, srcIp, dstIp)

		// If the ip is already a node then don't add another node
		_, ok := nodeMap[srcIp]
		if !ok {
			// If IP is localhost, then append port to the end

			// create node in the graph
			err := g.AddVertex(srcIp)
			if err != nil {
				panic(err)
			}

			// Add node in out map
			nodeMap[srcIp] = graphNode{
				Event: event,
				ip:    srcIp,
			}
		}
		_, ok = nodeMap[dstIp]
		if !ok {
			err := g.AddVertex(dstIp)
			if err != nil {
				panic(err)
			}

			nodeMap[dstIp] = graphNode{
				Event: event,
				ip:    dstIp,
			}
		}

		err := g.AddEdge(srcIp, dstIp)
		if err != nil {
			// panic(err)
		}
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

func getIp(event *types.Event, srcOrDst srcOrDst) string {
	if srcOrDst == src {
		return event.SrcEndpoint.L3Endpoint.Addr
	} else {
		return event.DstEndpoint.L3Endpoint.Addr
	}
}

func appendPorts(event *types.Event, srcIp string, dstIp string) (string, string) {
	if !(srcIp == dstIp) {
		return srcIp, dstIp
	}

	appSrcIp := srcIp + ":" + strconv.FormatUint(uint64(event.SrcEndpoint.Port), 10)
	appDstIp := dstIp + ":" + strconv.FormatUint(uint64(event.DstEndpoint.Port), 10)

	return appSrcIp, appDstIp
}
