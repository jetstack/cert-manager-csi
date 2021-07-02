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

package util

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/golang/glog"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
)

func MountPath(vol *csiapi.MetaData) string {
	return filepath.Join(vol.Path, "data")
}

// IsLikelyNotMountPoint determines if a directory is not a mountpoint.
// It is fast but not necessarily ALWAYS correct. If the path is in fact
// a bind mount from one part of a mount to another it will not be detected.
// It also can not distinguish between mountpoints and symbolic links.
// mkdir /tmp/a /tmp/b; mount --bind /tmp/a /tmp/b; IsLikelyNotMountPoint("/tmp/b")
// will return true. When in fact /tmp/b is a mount point. If this situation
// if of interest to you, don't use this function...
func IsLikelyMountPoint(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return false, err
	}
	rootStat, err := os.Stat(filepath.Dir(strings.TrimSuffix(file, "/")))
	if err != nil {
		return false, err
	}
	// If the directory has a different device as parent, then it is a mountpoint.
	if stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev {
		return true, nil
	}

	return false, nil
}

func Mount(source, target string, options []string) error {
	err := doMount(source, target, nil)
	if err != nil {
		return err
	}
	return nil
}

// Unmount unmounts the target.
func Unmount(target string) error {
	glog.V(4).Infof("Unmounting %s", target)
	command := exec.Command("umount", target)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unmount failed: %v\nUnmounting arguments: %s\nOutput: %s\n", err, target, string(output))
	}

	return nil
}

// doMount runs the mount command.
func doMount(source, target string, options []string) error {
	mountArgs := makeMountArgs(source, target, options)

	glog.V(4).Infof("Mounting cmd (mount) with arguments (%s)", mountArgs)
	command := exec.Command("mount", mountArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		args := strings.Join(mountArgs, " ")
		glog.Errorf("Mount failed: %v\nMounting command: mount\nMounting arguments: %s\nOutput: %s\n", err, args, string(output))
		return fmt.Errorf("mount failed: %v\nMounting command: mount\nMounting arguments: %s\nOutput: %s\n",
			err, args, string(output))
	}
	return err
}

// MakeMountArgs makes the arguments to the mount(8) command.
// Implementation is shared with NsEnterMounter
func makeMountArgs(source, target string, options []string) []string {
	// Build mount command as follows:
	//   mount [-t $fstype] [-o $options] [$source] $target
	mountArgs := []string{}
	options = append(options, "bind")
	mountArgs = append(mountArgs, "-o", strings.Join(options, ","))
	if len(source) > 0 {
		mountArgs = append(mountArgs, source)
	}
	mountArgs = append(mountArgs, target)

	return mountArgs
}
