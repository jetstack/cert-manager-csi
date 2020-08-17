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

package kind

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const (
	e2eImage = "cert-manager-csi-e2e:%s"
)

func (k *Kind) DeployCSIDriver(version string) error {
	log.Info("kind: building in tree CSI driver")

	csiPath := filepath.Join(k.rootPath, "./bin/cert-manager-csi")
	cmdPath := filepath.Join(k.rootPath, "./cmd/.")

	_, err := k.runCmd("go", "build", "-v", "-o", csiPath, cmdPath)
	if err != nil {
		return fmt.Errorf("failed to build CSI driver: %s", err)
	}

	image := fmt.Sprintf(e2eImage, version)
	log.Infof("kind: building CSI driver image %q", image)
	_, err = k.runCmd("docker", "build", "-t", image, k.rootPath)
	if err != nil {
		return fmt.Errorf("failed to build CSI docker image: %s", err)
	}

	tmpDir, err := ioutil.TempDir(os.TempDir(), "cert-manager-csi-e2e")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := k.loadImage(tmpDir, image); err != nil {
		return fmt.Errorf("failed to load CSI image: %s", err)
	}

	manifests, err := ioutil.ReadFile(
		filepath.Join(k.rootPath, "deploy", "cert-manager-csi-driver.yaml"))
	if err != nil {
		return err
	}

	manifests = bytes.ReplaceAll(manifests,
		[]byte("gcr.io/jetstack-josh/cert-manager-csi:v0.1.0-alpha.1"), []byte(image))

	deployPath := filepath.Join(tmpDir, "cert-manager-csi-driver.yaml")
	if err := ioutil.WriteFile(deployPath, manifests, 0644); err != nil {
		return err
	}

	if err := k.kubectlApplyF(deployPath); err != nil {
		return err
	}

	if err := k.waitForPodsReady("cert-manager", "app=cert-manager-csi"); err != nil {
		return err
	}

	return nil
}

func (k *Kind) loadImage(dir, image string) error {
	imageArchive := filepath.Join(dir, fmt.Sprintf("%s-e2e.tar", image))
	log.Infof("kind: saving image to archive %q", imageArchive)
	_, err := k.runCmd("docker", "save", "--output="+imageArchive, image)
	if err != nil {
		return err
	}

	nodes, err := k.ctx.ListNodes()
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(imageArchive)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		log.Infof("kind: loading image %q to node %q", image, node.Name())
		r := bytes.NewBuffer(b)
		if err := node.LoadImageArchive(r); err != nil {
			return err
		}

		err := node.Command("mkdir", "-p", "/tmp/cert-manager-csi").Run()
		if err != nil {
			return fmt.Errorf("failed to create directory %q: %s",
				"/tmp/cert-manager-csi", err)
		}
	}

	return nil
}
