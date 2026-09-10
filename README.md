# HyperDistillation

Show the potential of using eBPF tools to track network usage without depending on kubernetes for network infrastructure.

- There are many tools that track network usage through kubernetes but if the application does not use kubernetes, it becomes extremely hard to keep track of network usage and how API calls move from one application to another.
- This project will try to observe communication outside of kubernetes with a drop in docker container requiring no additional setup.
HyperDistillation utilises Inspektor Gadget, a set of tools and framework for data collection and system inspection on Kubernetes clusters and Linux hosts using eBPF. It traces network traﬀic between containers and hosts, outside of a Kubernetes cluster. This trace is visualised in the form of a dependency graph, with additional filtering capabilities.

[Project Report](./docs/HyperDistillation_Report.pdf)
