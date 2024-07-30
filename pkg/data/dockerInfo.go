package data

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func GetContainerData() (map[string]string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return nil, err
	}

	containerNameIp := make(map[string]string)

	// Iterate over each container and retrieve its name and IP address
	for _, container := range containers {
		containerName, _ := strings.CutPrefix(container.Names[0], "/")
		containerIP := container.NetworkSettings.Networks[container.HostConfig.NetworkMode].IPAddress

		containerNameIp[containerIP] = containerName
	}

	return containerNameIp, nil
}
