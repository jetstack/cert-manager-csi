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

package framework

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	crclientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/scheme"
	utilpointer "k8s.io/utils/pointer"

	csi "github.com/jetstack/cert-manager-csi/pkg/apis"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework/config"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework/helper"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework/testdata"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework/util"
)

// DefaultConfig contains the default shared config the is likely parsed from
// command line arguments.
var DefaultConfig = &config.Config{}

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	Config *config.Config

	// Kubernetes API clientsets
	KubeClientSet        kubernetes.Interface
	CertManagerClientSet crclientset.Interface

	// Namespace in which all test resources should reside
	Namespace *corev1.Namespace

	// To make sure that this framework cleans up after itself, no matter what,
	// we install a Cleanup action before each test and clear it after.  If we
	// should abort, the AfterSuite hook should run all Cleanup actions.
	cleanupHandle CleanupActionHandle

	testdata *testdata.TestData

	// The CA Issuer and ClusterIssuer to reference
	Issuer, ClusterIssuer cmmeta.ObjectReference

	helper *helper.Helper
}

func NewDefaultFramework(baseName string) *Framework {
	return NewFramework(baseName, DefaultConfig)
}

func NewFramework(baseName string, cfg *config.Config) *Framework {
	f := &Framework{
		Config:   cfg,
		BaseName: baseName,
	}

	BeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

func (f *Framework) BeforeEach() {
	f.helper = helper.NewHelper(f.Config)

	By("Creating a kubernetes client")
	kubeConfig, err := util.LoadConfig(f.Config.KubeConfigPath)
	Expect(err).NotTo(HaveOccurred())
	kubeConfig.ContentConfig = rest.ContentConfig{
		GroupVersion:         &corev1.SchemeGroupVersion,
		NegotiatedSerializer: scheme.Codecs,
	}

	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert manager client")
	f.CertManagerClientSet, err = crclientset.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Using the namespace " + f.Namespace.Name)

	By("Creating CA Issuer")
	f.Issuer, err = f.CreateCAIssuer(f.Namespace.Name, f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Creating CA ClusterIssuer")
	f.ClusterIssuer, err = f.CreateCAClusterIssuer(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Creating test data generator")
	f.testdata, err = testdata.New(time.Now().Unix(),
		[]string{f.Issuer.Name}, []string{f.ClusterIssuer.Name})
	Expect(err).NotTo(HaveOccurred())

	f.helper.RestConfig = kubeConfig
	f.helper.CMClient = f.CertManagerClientSet
	f.helper.KubeClient = f.KubeClientSet
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	if !f.Config.Cleanup {
		return
	}

	By("Deleting test namespace")
	err := f.DeleteKubeNamespace(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for test namespace to no longer exist")
	err = f.WaitForKubeNamespaceNotExist(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

func (f *Framework) RandomPod() *corev1.Pod {
	volumes := make([]corev1.Volume, (f.testdata.Int(10))+1)

	for i := range volumes {
		volumes[i] = corev1.Volume{
			Name: f.testdata.RandomName(),
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:           csi.GroupName,
					VolumeAttributes: f.testdata.RandomVolumeAttributes(),
				},
			},
		}
	}

	containers := make([]corev1.Container, f.testdata.Int(3)+1)
	for i := range containers {
		containers[i] = corev1.Container{
			Name:    f.testdata.RandomName(),
			Image:   "busybox",
			Command: []string{"sleep", "10000"},
		}

		// Set a random number of volumes taken from the pool of volume. Can and
		// will mount the same volume multiple times.
		for j := 0; j < (f.testdata.Int(len(volumes)) + 1); j++ {
			containers[i].VolumeMounts = append(containers[i].VolumeMounts,
				corev1.VolumeMount{
					Name:      volumes[f.testdata.Int(len(volumes))].Name,
					MountPath: f.testdata.RandomDirPath(),
				},
			)
		}
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: f.BaseName + "-",
			Namespace:    f.Namespace.Name,
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:  utilpointer.Int64Ptr(1000),
				RunAsGroup: utilpointer.Int64Ptr(3000),
				FSGroup:    utilpointer.Int64Ptr(1000),
			},
			Containers: containers,
			Volumes:    volumes,
		},
	}
}

func CasesDescribe(text string, body func()) bool {
	return Describe("[TEST] "+text, body)
}
