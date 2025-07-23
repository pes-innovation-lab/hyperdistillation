package gadgets

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/data"
	"github.com/PES-Innovation-Lab/hyperdistillation/pkg/graph"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

const (
	// The IP assoicated with all non-docker IP tcp events
	hostIP = "127.0.0.1"
	// The OCI artifact for the TraceTcp gadget
	tcpGadget = "ghcr.io/inspektor-gadget/gadget/trace_tcp:main"
	// The name used in the SrcContainerName/DstContainerName fields of the MetaEvent struct
	// when the tcp event is not associated with the container
	hostName = "HOST"
	// High priority to ensure the operator to runs last
	operatorPriority = 50_000
	// The runtime being used (make this modular? maybe a flag?)
	containerRuntime = "docker"
	runtimeSocket    = "/run/user/1000/podman/podman.sock" // Used for rootless podman, needs to be configured by user...
)

func TraceTcp() {
	var tcpEvents []*graph.MetaEvent

	ctx, cancel := context.WithCancel(context.Background())

	// Listen for SIGINT, generate DAG and exit gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Callback function run by TraceTcp operator when TraceTcp gadget captures an event
	TraceTcpCallback := func(source datasource.DataSource, data datasource.Data) error {
		event := graph.MetaEvent{}
		// TODO: add DstContainerName lookup (how?)
		var err error
		event.Type, err = source.GetField("type").String(data)
		if err != nil {
			return err
		}
		event.SrcContainerName, err = source.GetField("runtime.containerName").String(data)
		if err != nil {
			return err
		}
		event.SrcIp, err = source.GetField("src.addr").String(data)
		if err != nil {
			return err
		}
		event.DstIp, err = source.GetField("dst.addr").String(data)
		if err != nil {
			return err
		}
		tcpEvents = append(tcpEvents, &event)
		// fmt.Printf("made TCP %s (%s) from %s to %s\n", event.Type, event.SrcContainerName, event.SrcIp, event.DstIp)
		fmt.Printf("\n\nDocker API: Src Container Name: %s, Dst Container Name: %s\n", event.SrcContainerName, event.DstContainerName)
		fmt.Printf("Docker API: Src Container IP: %s, Dst Container IP: %s\n", event.SrcIp, event.DstIp)

		// TODO: finish rest of trace (is it required? Lots of dynamic access required)

		// fmt.Printf("\nTrace Data: Runtime: %s, Container ID: %s, Container Name: %s, Container Image Name: %s, Container Image Digest: %s\n", source.Runtime.RuntimeName, event.Runtime.ContainerID, event.Runtime.ContainerName, event.Runtime.ContainerImageName, event.Runtime.ContainerImageDigest)
		// fmt.Printf("Trace Data: Timestamp: %v, Type: %s, Message: %s, Mount Namespace: %v\n", event.Timestamp, event.Type, event.Message, event.MountNsID)
		// fmt.Printf("Trace Data: Operation: %s, Pid: %d, Uid: %d ,Gid: %d, Comm: %s, IP version: %d\n", event.Operation, event.Pid, event.Uid, event.Gid, event.Comm, event.IPVersion)
		// fmt.Printf("Trace Data: Src Endpoint: %v, Src Port: %d, Src Proto: %d, Dst Endpoint: %v, Dst Port: %d, Dst Proto: %d\n", event.SrcEndpoint.L3Endpoint, event.SrcEndpoint.Port, event.SrcEndpoint.Proto, event.DstEndpoint.L3Endpoint, event.DstEndpoint.Port, event.DstEndpoint.Proto)

		fmt.Printf("Meta Event Created: %v\n", event)
		return nil
	}

	// Init function for TraceTcp operator
	TraceTcpInit := func(gadgetCtx operators.GadgetContext) error {
		dataSource, dsExists := gadgetCtx.GetDataSources()["tracetcp"]
		if dsExists {
			dataSource.Subscribe(TraceTcpCallback, operatorPriority)
		}
		return nil
	}

	// Create the operator to be activated when event is captured.
	tcpOperator := simple.New("TcpOperator",
		simple.OnInit(TraceTcpInit),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		fmt.Printf("Runtime init error: %v", err)
		cancel()
		return
	}
	defer runtime.Close()

	// Creates an operator to enrich output with the container-name and restrict output to containers.
	localManagerOperator := localmanager.LocalManagerOperator
	localManagerParams := localManagerOperator.GlobalParamDescs().ToParams()
	localManagerParams.Get(localmanager.Runtimes).Set(containerRuntime)
	localManagerParams.Get(localmanager.DockerSocketPath).Set(runtimeSocket)

	// Do we need to handle connections made by the host? If so, this is required, but it doesn't seem to work.
	// localManagerParams.AddKeyValuePair(localmanager.Host, "true")

	if err := localManagerOperator.Init(localManagerParams); err != nil {
		fmt.Printf("init local manager: %v", err)
		cancel()
		return
	}
	defer localManagerOperator.Close()

	gadgetErr := make(chan error, 1)
	// Creates a context with the required gadget and its associated operators.
	gadgetCtx := gadgetcontext.New(
		ctx,
		tcpGadget,
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler,
			localManagerOperator,
			formatters.FormattersOperator,
			tcpOperator,
		),
	)
	go func() {
		err := runtime.RunGadget(gadgetCtx, nil, nil)
		if err != nil {
			gadgetErr <- err
		}
	}()
	select {
	case <-sigChan:
		fmt.Printf("\n\nSTOPPING TRACE AND GENERATING LOGS\n")
		gadgetCtx.StopLocalOperators()
		cancel()
		data.MarshalMetaEvent(data.DefaultFileName, tcpEvents)
	case err := <-gadgetErr:
		fmt.Printf("running gadget: %v", err)
		cancel()
	}
}
