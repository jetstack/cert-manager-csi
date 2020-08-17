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

package driver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jetstack/cert-manager-csi/pkg/apis/defaults"
	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/apis/validation"
	"github.com/jetstack/cert-manager-csi/pkg/certmanager"
	"github.com/jetstack/cert-manager-csi/pkg/renew"
	"github.com/jetstack/cert-manager-csi/pkg/util"
)

const (
	kib int64 = 1024

	maxStorageCapacity = 100 * kib

	deviceIDKey = "deviceID"
)

type NodeServer struct {
	nodeID   string
	dataRoot string

	cm      *certmanager.CertManager
	renewer *renew.Renewer
}

func NewNodeServer(nodeID, dataRoot, tmpfsSize string) (*NodeServer, error) {
	cm, err := certmanager.New()
	if err != nil {
		return nil, err
	}

	renewer := renew.New(dataRoot, cm.RenewCertificate)

	if err := renewer.Discover(); err != nil {
		glog.Errorf("renewer: %s", err)
	}

	return &NodeServer{
		nodeID:   nodeID,
		dataRoot: dataRoot,
		renewer:  renewer,
		cm:       cm,
	}, nil
}

func (ns *NodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	attr := req.GetVolumeContext()
	targetPath := req.GetTargetPath()

	if err := ns.validateVolumeAttributes(req); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	attr, err := defaults.SetDefaultAttributes(attr)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := validation.ValidateAttributes(attr); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	volID := req.GetVolumeId()
	vol, err := ns.createVolume(volID, targetPath, attr)
	if err != nil && !os.IsExist(err) {
		glog.Error("node: failed to create volume: ", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	glog.Infof("node: created volume: %s", vol.Path)

	glog.Infof("node: creating key/cert pair with cert-manager: %s", vol.Path)

	keyBundle, err := util.NewRSAKey()
	if err != nil {
		return nil, err
	}

	cert, err := ns.cm.EnsureCertificate(vol, keyBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create new certificate: %s", err)
	}

	if s, ok := attr[csiapi.DisableAutoRenewKey]; !ok || s != "true" {
		if err := ns.renewer.WatchCert(vol, cert.NotBefore, cert.NotAfter); err != nil {
			return nil, fmt.Errorf("failed to watch file %s:%s:%s: %s",
				attr[csiapi.CSIPodNamespaceKey], attr[csiapi.CSIPodNameKey], vol.ID, err)
		}
	}

	if err := util.WriteMetaDataFile(vol); err != nil {
		return nil, fmt.Errorf("failed to write metadata file: %s", err)
	}

	mountPath := util.MountPath(vol)

	mntPoint, err := util.IsLikelyMountPoint(targetPath)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(targetPath, 0700); err != nil {
			return nil, status.Error(codes.Internal,
				fmt.Sprintf("failed to create target path directory %s: %s", targetPath, err))
		}

		mntPoint = false
	}

	if err = os.MkdirAll(mountPath, 0700); err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("failed to create mount path directory %s: %s", mountPath, err))
	}

	// we are already mounted so assume certs have to be written
	if mntPoint {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	glog.V(4).Infof("node: publish volume request ~ target:%v volumeId:%v attributes:%v",
		targetPath, volID, attr)

	if err := util.Mount(mountPath, targetPath, []string{"ro"}); err != nil {
		if rmErr := os.RemoveAll(vol.Path); rmErr != nil && !os.IsNotExist(rmErr) {
			err = fmt.Errorf("failed to remove all from %s: %s,%s", vol.Path, err, rmErr)
		}

		return nil, status.Error(codes.Internal,
			fmt.Sprintf("failed to mount path %s -> %s: %s", mountPath, targetPath, err))
	}

	// We need to ensure unix permissions if the file already exists
	if err := os.Chmod(targetPath, 700); err != nil {
		return nil, err
	}

	glog.V(2).Infof("node: mount successful %s:%s:%s",
		attr[csiapi.CSIPodNamespaceKey], attr[csiapi.CSIPodNameKey], vol.ID)

	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *NodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	targetPath := req.GetTargetPath()
	volumeID := req.GetVolumeId()

	// Check arguments
	if len(targetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "volume ID missing in request")
	}

	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "target path missing in request")
	}

	// kill the renewal Go routine watching this volume
	ns.renewer.KillWatcher(volumeID)

	// Unmounting the image
	err := util.Unmount(targetPath)
	if err != nil {
		return nil, nil
	}
	glog.V(4).Infof("node: volume %s/%s has been unmounted.", targetPath, volumeID)

	glog.V(4).Infof("node: deleting volume %s", volumeID)

	path := filepath.Join(ns.dataRoot, volumeID)
	if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *NodeServer) validateVolumeAttributes(req *csi.NodePublishVolumeRequest) error {
	var errs []string

	attr := req.GetVolumeContext()

	// Kubernetes 1.15 doesn't have csi.storage.k8s.io/ephemeral.
	ephemeralVolume :=
		(attr[csiapi.CSIEphemeralKey] == "true" || attr[csiapi.CSIEphemeralKey] == "")
	if !ephemeralVolume {
		errs = append(errs, "publishing a non-ephemeral volume mount is not supported")
	}

	_, okN := attr[csiapi.CSIPodNameKey]
	_, okNs := attr[csiapi.CSIPodNamespaceKey]
	if !okN || !okNs {
		errs = append(errs, fmt.Sprintf("expecting both %s and %s attributes to be set in context",
			csiapi.CSIPodNamespaceKey, csiapi.CSIPodNameKey))
	}

	if c := req.GetVolumeCapability(); c == nil {
		errs = append(errs, "volume capability missing")
	} else {
		if c.GetBlock() != nil {
			errs = append(errs, "block access type not supported")
		}
	}
	if len(req.GetVolumeId()) == 0 {
		errs = append(errs, "volume ID missing")
	}
	if len(req.GetTargetPath()) == 0 {
		errs = append(errs, "target path missing")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}

	return nil
}

// createVolume create the directory for the volume. It returns the volume
// path or err if one occurs.
func (ns *NodeServer) createVolume(id, targetPath string,
	attr map[string]string) (*csiapi.MetaData, error) {
	podName := attr[csiapi.CSIPodNameKey]

	name := util.BuildVolumeName(podName, id)
	path := filepath.Join(ns.dataRoot, id)

	err := os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	vol := &csiapi.MetaData{
		ID:         id,
		Name:       name,
		Size:       maxStorageCapacity,
		Path:       path,
		TargetPath: targetPath,
		Attributes: attr,
	}

	return vol, nil
}

func (ns *NodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

func (ns *NodeServer) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	glog.Info("node: getting default node info")

	return &csi.NodeGetInfoResponse{
		NodeId: ns.nodeID,
	}, nil
}

func (ns *NodeServer) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

func (ns *NodeServer) NodeGetVolumeStats(ctx context.Context, in *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

func (ns *NodeServer) NodeExpandVolume(ctx context.Context, in *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

func (ns *NodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
