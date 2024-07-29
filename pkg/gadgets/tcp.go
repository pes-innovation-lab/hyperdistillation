package gadgets

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

func TraceTcp() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	var tcpEvents []*types.Event

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		// Store all events
		tcpEvents = append(tcpEvents, event)

		fmt.Printf("\nRuntime: %s, Container ID: %s, Container Name: %s, Container Image Name: %s, Container Image Digest: %s\n", event.Runtime.RuntimeName, event.Runtime.ContainerID, event.Runtime.ContainerName, event.Runtime.ContainerImageName, event.Runtime.ContainerImageDigest)
		fmt.Printf("Timestamp: %v, Type: %s, Message: %s, Mount Namespace: %v\n", event.Timestamp, event.Type, event.Message, event.MountNsID)
		fmt.Printf("Operation: %s, Pid: %d, Uid: %d ,Gid: %d, Comm: %s, IP version: %d\n", event.Operation, event.Pid, event.Uid, event.Gid, event.Comm, event.IPVersion)
		fmt.Printf("Src Endpoint: %v, Src Port: %d, Src Proto: %d, Dst Endpoint: %v, Dst Port: %d, Dst Proto: %d\n", event.SrcEndpoint.L3Endpoint, event.SrcEndpoint.Port, event.SrcEndpoint.Proto, event.DstEndpoint.L3Endpoint, event.DstEndpoint.Port, event.DstEndpoint.Proto)
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.

	tracer, err := tracer.NewTracer(&tracer.Config{}, nil, eventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}

	// Listen for SIGINT, generate DAG and exit gracefully
	sigChan := make(chan os.Signal, 1)
	exit := make(chan struct{}, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan

		fmt.Printf("\n\n STOPPING TRACE AND GENERATING GRAPHS\n")
		graph.GenerateGraph(tcpEvents)
		tracer.Stop()

		exit <- struct{}{}
	}()

	<-exit
}
