package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	// "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	// "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	// "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
)

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Define a callback to be called each time there is an event.

	eventCallback := func(event *types.Event) {
		fmt.Printf("A new %q process with pid %d was executed\n",
			event.Comm, event.Pid)
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.

	tracer, err := tracer.NewTracer(&tracer.Config{}, nil, eventCallback)

	// tracer , err := tracer.NewTracer()
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()
	// defer tracer.Close()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
