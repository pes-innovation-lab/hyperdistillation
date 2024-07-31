package gadgets

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/data"
	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"
	"github.com/cilium/ebpf/rlimit"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerUtilTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	igTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func HyperTcp() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	err := rlimit.RemoveMemlock()
	if err != nil {
		return
	}

	// Create and initialize the container collection
	containerCollection := &containercollection.ContainerCollection{}

	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		fmt.Printf("failed to create trace-collection: %s\n", err)
		return
	}
	defer tracerCollection.Close()

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		// Indicate the callback that will be invoked each time
		// there is an event
		containercollection.WithPubSub(tracerCollection.TracerMapsUpdater()),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Enrich events with Linux namespaces information
		// It's needed to be able to filter by containers in this example.
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the container
		// runtime. docker and containerd in this case.
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerUtilTypes.RuntimeConfig{
				{Name: igTypes.RuntimeNameDocker},
				{Name: igTypes.RuntimeNameContainerd},
				// {Name: igTypes.RuntimeNamePodman},
				// {Name: igTypes.RuntimeNameCrio},
				// {Name: igTypes.RuntimeNameUnknown},
			}),
	}

	if err := containerCollection.Initialize(opts...); err != nil {
		fmt.Printf("failed to initialize container collection: %s\n", err)
		return
	}
	defer containerCollection.Close()

	var tcpEvents []*graph.MetaEvent

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		// containerNameIP, err := data.GetContainerData()

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

		srcContainerName, isContainer := event.Runtime.ContainerName, false
		if srcContainerName != "" {
			isContainer = true
		}
		_, isHost := hostAddresses[event.SrcEndpoint.Addr]
		if isContainer {
			metaEvent.SrcIp = event.SrcEndpoint.Addr
			metaEvent.SrcContainerName = srcContainerName
		} else if isHost {
			metaEvent.SrcIp = hostIP
			metaEvent.SrcContainerName = hostName
		} else {
			metaEvent.SrcIp = event.SrcEndpoint.Addr
			metaEvent.SrcContainerName = event.SrcEndpoint.Addr
		}

		dstContainerName, isContainer := event.Runtime.ContainerName, false
		if dstContainerName != "" {
			isContainer = true
		}
		_, isHost = hostAddresses[event.DstEndpoint.Addr]
		if isContainer {
			metaEvent.DstIp = event.DstEndpoint.Addr
			metaEvent.DstContainerName = dstContainerName
		} else if isHost {
			metaEvent.DstIp = hostIP
			metaEvent.DstContainerName = hostName
		} else {
			metaEvent.DstIp = event.DstEndpoint.Addr
			metaEvent.DstContainerName = event.DstEndpoint.Addr
		}

		if !(metaEvent.SrcContainerName == hostName && !isContainer) {
			// Store events
			tcpEvents = append(tcpEvents, &metaEvent)
		}

		fmt.Printf("\n\nTrace Data: Runtime: %s, Container ID: %s, Container Name: %s, Container Image Name: %s, Container Image Digest: %s\n", event.Runtime.RuntimeName, event.Runtime.ContainerID, event.Runtime.ContainerName, event.Runtime.ContainerImageName, event.Runtime.ContainerImageDigest)
		fmt.Printf("Trace Data: Timestamp: %v, Type: %s, Message: %s, Mount Namespace: %v\n", event.Timestamp, event.Type, event.Message, event.MountNsID)
		fmt.Printf("Trace Data: Operation: %s, Pid: %d, Uid: %d ,Gid: %d, Comm: %s, IP version: %d\n", event.Operation, event.Pid, event.Uid, event.Gid, event.Comm, event.IPVersion)
		fmt.Printf("Trace Data: Src Endpoint: %v, Src Port: %d, Src Proto: %d, Dst Endpoint: %v, Dst Port: %d, Dst Proto: %d\n", event.SrcEndpoint.L3Endpoint, event.SrcEndpoint.Port, event.SrcEndpoint.Proto, event.DstEndpoint.L3Endpoint, event.DstEndpoint.Port, event.DstEndpoint.Proto)

		fmt.Printf("Meta Event Created: %v\n", metaEvent)
	}

	// Create the tracer
	// tracer, err := tracer.NewTracer(&tracer.Config{MountnsMap: mountnsmap}, containerCollection, eventCallback)
	tracer, err := tracer.NewTracer(&tracer.Config{}, containerCollection, eventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	// Listen for SIGINT, generate logs and exit gracefully
	sigChan := make(chan os.Signal, 1)
	exit := make(chan struct{}, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan

		fmt.Printf("\n\nSTOPPING TRACE AND GENERATING LOGS\n")
		tracer.Stop()
		data.MarshalMetaEvent(data.DefaultFileName, tcpEvents)

		exit <- struct{}{}
	}()

	<-exit
}
