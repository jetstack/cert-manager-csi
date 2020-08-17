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

package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/kind/pkg/cluster/nodes"

	csidefaults "github.com/jetstack/cert-manager-csi/pkg/apis/defaults"
	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/util"
)

func (h *Helper) MetaDataCertificateKeyExistInHostPath(cr *cmapi.CertificateRequest,
	pod *corev1.Pod, attr map[string]string, podMountPath, dataDir string) error {
	volID := util.BuildVolumeID(string(pod.UID), podMountPath)
	volName := util.BuildVolumeName(pod.Name, volID)
	dirPath := filepath.Join(dataDir, volID)

	// set defaults and csi storage attrubutes from pod
	attr, err := csidefaults.SetDefaultAttributes(attr)
	if err != nil {
		return fmt.Errorf("failed to set default volume attributes: %s", err)
	}

	attr["csi.storage.k8s.io/ephemeral"] = "true"
	attr["csi.storage.k8s.io/pod.name"] = pod.Name
	attr["csi.storage.k8s.io/pod.namespace"] = pod.Namespace
	attr["csi.storage.k8s.io/pod.uid"] = string(pod.UID)
	attr["csi.storage.k8s.io/serviceAccount.name"] = pod.Spec.ServiceAccountName

	node, err := h.cfg.Environment.Node(pod.Spec.NodeName)
	if err != nil {
		return err
	}

	if err := h.matchFilePerm(node, dirPath, "755"); err != nil {
		return err
	}

	metaPath := filepath.Join(dirPath, "metadata.json")
	if err := h.matchFilePerm(node, metaPath, "600"); err != nil {
		return err
	}

	metaDataData, err := h.readFile(node, metaPath)
	if err != nil {
		return err
	}

	expMetaData := &csiapi.MetaData{
		ID:   volID,
		Name: volName,
		Size: 102400,
		Path: filepath.Join("/csi-data-dir", volID),
		TargetPath: fmt.Sprintf("/var/lib/kubelet/pods/%s/volumes/kubernetes.io~csi/%s/mount",
			string(pod.UID), podMountPath),
		Attributes: attr,
	}

	gotMetaData := new(csiapi.MetaData)
	if err := json.Unmarshal(metaDataData, gotMetaData); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %s", err)
	}

	if err := h.metaDataMatches(expMetaData, gotMetaData); err != nil {
		return fmt.Errorf("bad metadata at %q: %s", metaPath, err)
	}

	dataDirPath := filepath.Join(dirPath, "data")
	if err := h.matchFilePerm(node, dataDirPath, "755"); err != nil {
		return err
	}

	certPath := attr[csiapi.CertFileKey]
	certPath = filepath.Join(dataDirPath, certPath)
	if err := h.matchFilePerm(node, certPath, "644"); err != nil {
		return err
	}

	keyPath := attr[csiapi.KeyFileKey]
	keyPath = filepath.Join(dataDirPath, keyPath)
	if err := h.matchFilePerm(node, keyPath, "644"); err != nil {
		return err
	}

	caPath := attr[csiapi.CAFileKey]
	caPath = filepath.Join(dataDirPath, caPath)
	if err := h.matchFilePerm(node, caPath, "644"); err != nil {
		return err
	}

	certData, err := h.readFile(node, certPath)
	if err != nil {
		return err
	}
	keyData, err := h.readFile(node, keyPath)
	if err != nil {
		return err
	}

	return h.CertificateKeyMatch(cr, certData, keyData)
}

func (h *Helper) readFile(node *nodes.Node, path string) ([]byte, error) {
	// TODO (@joshvanl): use tar compression
	execOut, execErr := new(bytes.Buffer), new(bytes.Buffer)
	cmd := node.Command("cat", path)
	cmd.SetStdout(execOut)
	cmd.SetStderr(execErr)

	if err := cmd.Run(); err != nil {
		log.Errorf("helper: cat %q failed: %s", path, execErr.String())
		return nil, err
	}

	return execOut.Bytes(), nil
}

func (h *Helper) matchFilePerm(node *nodes.Node, path string, perm string) error {
	execOut, execErr := new(bytes.Buffer), new(bytes.Buffer)
	foo := new(bytes.Buffer)

	fooCmd := node.Command("ls", "-la", path)
	fooCmd.SetStdout(foo)
	if err := fooCmd.Run(); err != nil {
		return fmt.Errorf("failed to run ls: %s", err)
	}

	cmd := node.Command("stat", "-c", "%a", path)
	cmd.SetStdout(execOut)
	cmd.SetStderr(execErr)

	if err := cmd.Run(); err != nil {
		log.Errorf("helper: stat failed: %s", execErr.String())
		pathD := filepath.Dir(path)

		cmd := node.Command("ls", "-la", pathD)
		cmd.SetStdout(execOut)
		if lErr := cmd.Run(); lErr == nil {
			log.Infof("helper: ls -la %q: %s\n",
				pathD, execOut.String())
		}

		return fmt.Errorf("failed to get stat of file %q: %s",
			path, err)
	}

	if strings.TrimSpace(execOut.String()) != perm {
		return fmt.Errorf("expected %q to have permissions %s but got %s\n%s\n",
			path, perm, execOut.String(), foo.String())
	}

	return nil
}
