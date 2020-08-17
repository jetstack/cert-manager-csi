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
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	certManagerManifestPath = "https://github.com/jetstack/cert-manager/releases/download/v%s/cert-manager.yaml"
)

func (k *Kind) DeployCertManager(version string) error {
	log.Infof("kind: deploying cert-manager version %q", version)

	if !strings.HasPrefix(version, "file://") {
		log.Info("kind: numeric version found so deploying remote image")

		path := fmt.Sprintf(certManagerManifestPath, version)
		if err := k.kubectlApplyF(path); err != nil {
			return err
		}

	} else {
		log.Infof("kind: file version found so building images from source")

		cmRepoRoot := strings.Replace(version, "file://", "", 1)

		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		if err := os.Chdir(cmRepoRoot); err != nil {
			return err
		}
		defer os.Chdir(wd)

		out, err := k.runCmd("go", "run",
			"./hack/release/main.go",
			"--repo-root="+cmRepoRoot,
			"--images",
			"--images.export=true",
			"--images.goarch=amd64",
			"--app-version=v0.1.0-csi",
			"--manifests",
			"--docker-repo=cert-manager-csi",
		)
		if err != nil {
			return fmt.Errorf("failed to build cert-manager images and manifests from file: %s", err)
		}

		tmpDir, err := ioutil.TempDir(os.TempDir(), "cert-manager-csi-e2e")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)

		if err := os.Mkdir(filepath.Join(tmpDir,
			"cert-manager-csi"), 0755); err != nil {
			return err
		}

		for _, image := range []string{
			"cert-manager-csi/cert-manager-controller-amd64:v0.1.0-csi",
			"cert-manager-csi/cert-manager-cainjector-amd64:v0.1.0-csi",
			"cert-manager-csi/cert-manager-webhook-amd64:v0.1.0-csi",
		} {
			if err := k.loadImage(tmpDir, image); err != nil {
				return err
			}
		}

		// TODO (@joshvanl): update cert-manager to expose target manifests build
		// so it doesn't require a log parse hack

		// get manifests target path from log output
		var manifestsPath string
		for _, l := range out {
			if strings.Contains(l, "cert-manager.yaml") {
				for _, ll := range strings.Split(l, " ") {
					if strings.HasPrefix(ll, `"path"="`) {
						manifestsPath = strings.Split(ll, `"`)[3]
						break
					}
				}
			}
		}

		log.Infof("kind: deploying manifests file %q", manifestsPath)
		manifests, err := ioutil.ReadFile(manifestsPath)
		if err != nil {
			return err
		}

		manifests = bytes.ReplaceAll(manifests, []byte(`image: "quay.io/jetstack/cert-manager-controller`), []byte(`image: "cert-manager-csi/cert-manager-controller-amd64`))
		manifests = bytes.ReplaceAll(manifests, []byte(`image: "quay.io/jetstack/cert-manager-cainjector`), []byte(`image: "cert-manager-csi/cert-manager-cainjector-amd64`))
		manifests = bytes.ReplaceAll(manifests, []byte(`image: "quay.io/jetstack/cert-manager-webhook`), []byte(`image: "cert-manager-csi/cert-manager-webhook-amd64`))

		if err := k.kubectlApplyF("-", manifests); err != nil {
			return err
		}
	}

	if err := k.waitForPodsReady(
		"cert-manager", "app.kubernetes.io/instance=cert-manager"); err != nil {
		return err
	}

	return nil
}

func (k *Kind) ensureKubectl() error {
	binPath := filepath.Join(k.rootPath, "bin")
	kubectlPath := filepath.Join(binPath, "kubectl")
	log.Infof("kind: ensuring kubectl is present at %q", kubectlPath)

	err := os.MkdirAll(binPath, 0744)
	if err != nil {
		return err
	}

	s, err := os.Stat(kubectlPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		urlPath := fmt.Sprintf(kubectlURL, runtime.GOOS)
		log.Infof("kind: downloading kubectl from %q", urlPath)
		if err := downloadFile(kubectlPath, urlPath); err != nil {
			return err
		}

	} else {
		if s.IsDir() {
			return fmt.Errorf("kubectl filepath is directory %q", kubectlPath)
		}
	}

	if err := os.Chmod(kubectlPath, 0744); err != nil {
		return err
	}

	f, err := os.Open(kubectlPath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	fileHash := fmt.Sprintf("%x", h.Sum(nil))

	switch runtime.GOOS {
	case "linux":
		if fileHash != kubectlSHALinux {
			return fmt.Errorf("file hash did not match expected %s != (%q) %s",
				kubectlSHALinux, kubectlPath, fileHash)
		}

	case "darwin":
		if fileHash != kubectlSHADarwin {
			return fmt.Errorf("file hash did not match expected %s != (%q) %s",
				kubectlSHADarwin, kubectlPath, fileHash)
		}

	default:
		return fmt.Errorf("unsupported OS %q", runtime.GOOS)
	}

	return nil
}

func (k *Kind) kubectlApplyF(manifestPath string, ins ...[]byte) error {
	log.Infof("kind: applying manifests %s", manifestPath)

	if err := k.ensureKubectl(); err != nil {
		return fmt.Errorf("failed to ensure kubectl binary: %s", err)
	}

	kubectlPath := filepath.Join(k.rootPath, "bin", "kubectl")

	cmd := exec.Command(kubectlPath,
		"--kubeconfig="+k.ctx.KubeConfigPath(),
		"apply",
		"-f",
		manifestPath)

	wc, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if len(ins) > 0 {
		go func() {
			defer wc.Close()
			for _, i := range ins {
				wc.Write(i)
			}
		}()
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("failed to run apply on %q: %s", manifestPath, err)
	}

	return nil
}

func (k *Kind) runCmd(command string, args ...string) ([]string, error) {
	log.Infof("kind: running command '%s %s'", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)

	cmd.Stdout = os.Stdout
	cmd.Env = append(cmd.Env,
		"GO111MODULE=on", "CGO_ENABLED=0", "HOME="+os.Getenv("HOME"),
		"PATH="+os.Getenv("PATH"))

	pr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	bs := bufio.NewScanner(pr)

	var out []string

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		for bs.Scan() {
			log.Infof("kind (exec): %s", bs.Text())
			out = append(out, bs.Text())
		}
		wg.Done()
	}()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return out, err
	}
	wg.Wait()

	return out, nil
}
