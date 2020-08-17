/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package environment

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/kind/pkg/cluster/nodes"

	"github.com/jetstack/cert-manager-csi/test/kind"
)

const (
	defaultNodeImage          = "1.16.1"
	defaultCertManagerVersion = "0.16.1"
	defaultRootPath           = "../../../."
)

type Environment struct {
	kind     *kind.Kind
	rootPath string
}

func Create(masterNodes, workerNodes int) (*Environment, error) {
	nodeImage := os.Getenv("CERT_MANAGER_CSI_K8S_VERSION")
	if nodeImage == "" {
		nodeImage = defaultNodeImage
	}
	nodeImage = fmt.Sprintf("kindest/node:v%s", nodeImage)

	certManagerVersion := os.Getenv("CERT_MANAGER_CSI_CERT_MANAGER_VERSION")
	if certManagerVersion == "" {
		certManagerVersion = defaultCertManagerVersion
	}

	rootPath := os.Getenv("CERT_MANAGER_CSI_ROOT_PATH")
	if rootPath == "" {
		rootPath = defaultRootPath
	}

	rPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path %q: %s",
			rootPath, err)
	}

	k, err := kind.New(rPath, nodeImage, masterNodes, workerNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to create kind cluster: %s", err)
	}

	if err := k.DeployCertManager(certManagerVersion); err != nil {
		return nil, fmt.Errorf("failed to deploy cert-manager: %s", err)
	}

	if err := k.DeployCSIDriver("canary"); err != nil {
		return nil, fmt.Errorf("failed to deploy cert-manager-csi driver: %s", err)
	}

	return &Environment{
		kind:     k,
		rootPath: rootPath,
	}, nil
}

func (e *Environment) Destory() error {
	if e.kind != nil {
		if err := e.kind.Destroy(); err != nil {
			return err
		}
	}

	return nil
}

func (e *Environment) KubeClient() *kubernetes.Clientset {
	return e.kind.KubeClient()
}

func (e *Environment) KubeConfigPath() string {
	return e.kind.KubeConfigPath()
}

func (e *Environment) RootPath() string {
	return e.rootPath
}

func (e *Environment) Node(name string) (*nodes.Node, error) {
	ns, err := e.kind.Nodes()
	if err != nil {
		return nil, err
	}

	var node *nodes.Node
	for _, n := range ns {
		if n.Name() == name {
			node = &n
			break
		}
	}

	if node == nil {
		return nil, fmt.Errorf("failed to find node %q", name)
	}

	return node, nil
}
