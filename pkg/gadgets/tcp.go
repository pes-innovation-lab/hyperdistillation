package gadgets

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/data"
	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

const (
	// The IP assoicated with all non-docker IP tcp events
	hostIP = "127.0.0.1"

	// The name used in the SrcContainerName/DstContainerName fields of the MetaEvent struct
	// when the tcp event is not associated with the container
	hostName = "HOST"
)

func TraceTcp() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	var tcpEvents []*graph.MetaEvent

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		containerNameIP, err := data.GetContainerData()

		if err != nil {
			fmt.Printf("error: %v", err)
		}

		metaEvent := graph.MetaEvent{
			Event: event,
		}

		hostAddresses, err := data.GetHostIPs()
		if err != nil {
			fmt.Printf("error: %v", err)
		}

		srcContainerName, isContainer := containerNameIP[event.SrcEndpoint.Addr]
		_, isHost := hostAddresses[event.SrcEndpoint.Addr]
		if isContainer {
			metaEvent.SrcIp = event.SrcEndpoint.Addr
			metaEvent.SrcContainerName = srcContainerName
		} else if isHost {
			metaEvent.SrcIp = hostIP
			metaEvent.SrcContainerName = hostName
		} else {
			metaEvent.SrcIp = event.SrcEndpoint.Addr
			metaEvent.SrcContainerName = metaEvent.SrcIp
		}

		dstContainerName, isContainer := containerNameIP[event.DstEndpoint.Addr]
		_, isHost = hostAddresses[event.DstEndpoint.Addr]
		if isContainer {
			metaEvent.DstIp = event.DstEndpoint.Addr
			metaEvent.DstContainerName = srcContainerName
		} else if isHost {
			metaEvent.DstIp = hostIP
			metaEvent.DstContainerName = hostName
		} else {
			metaEvent.DstIp = event.DstEndpoint.Addr
			metaEvent.DstContainerName = metaEvent.DstIp
		}

		// Store all events
		tcpEvents = append(tcpEvents, &metaEvent)

		fmt.Printf("Docker API: Src Container Name: %s, Dst Container Name: %s", srcContainerName, dstContainerName)
		fmt.Printf("Docker API: Src Container IP: %s, Dst Container IP: %s", metaEvent.SrcIp, metaEvent.DstIp)
		// fmt.Printf("\nTrace Data: Runtime: %s, Container ID: %s, Container Name: %s, Container Image Name: %s, Container Image Digest: %s\n", event.Runtime.RuntimeName, event.Runtime.ContainerID, event.Runtime.ContainerName, event.Runtime.ContainerImageName, event.Runtime.ContainerImageDigest)
		fmt.Printf("Trace Data: Timestamp: %v, Type: %s, Message: %s, Mount Namespace: %v\n", event.Timestamp, event.Type, event.Message, event.MountNsID)
		fmt.Printf("Trace Data: Operation: %s, Pid: %d, Uid: %d ,Gid: %d, Comm: %s, IP version: %d\n", event.Operation, event.Pid, event.Uid, event.Gid, event.Comm, event.IPVersion)
		fmt.Printf("Trace Data: Src Endpoint: %v, Src Port: %d, Src Proto: %d, Dst Endpoint: %v, Dst Port: %d, Dst Proto: %d\n", event.SrcEndpoint.L3Endpoint, event.SrcEndpoint.Port, event.SrcEndpoint.Proto, event.DstEndpoint.L3Endpoint, event.DstEndpoint.Port, event.DstEndpoint.Proto)
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
