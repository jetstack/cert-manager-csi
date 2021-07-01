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

package cases

import (
	"context"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	csi "github.com/jetstack/cert-manager-csi/pkg/apis"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework"
	"github.com/jetstack/cert-manager-csi/test/e2e/util"
)

var _ = framework.CasesDescribe("Normal CSI behaviour", func() {
	f := framework.NewDefaultFramework("stress-test")

	It("should create a pod with a single volume key pair mounted with all attributes set", func() {
		testVolume := corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   csi.GroupName,
					ReadOnly: boolPtr(true),
					VolumeAttributes: map[string]string{
						"csi.cert-manager.io/issuer-name":  f.Issuer.Name,
						"csi.cert-manager.io/issuer-kind":  f.Issuer.Kind,
						"csi.cert-manager.io/issuer-group": f.Issuer.Group,
						"csi.cert-manager.io/dns-names":    "a.example.com,b.example.com",
						"csi.cert-manager.io/uri-sans":     "spiffe://my-service.sandbox.cluster.local,http://foo.bar",
						"csi.cert-manager.io/ip-sans":      "192.168.0.1,123.4.5.6",
						"csi.cert-manager.io/duration":     "123h",
						"csi.cert-manager.io/is-ca":        "true",
						"csi.cert-manager.io/common-name":  "foo-bar",
					},
				},
			},
		}

		testPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: f.BaseName + "-",
				Namespace:    f.Namespace.Name,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					corev1.Container{
						Name:    "test-container-1",
						Image:   "busybox",
						Command: []string{"sleep", "10000"},
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/tls",
								Name:      "tls",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					testVolume,
				},
			},
		}

		By("Creating a Pod")
		testPod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(context.TODO(), testPod, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Pod to become ready")
		err = f.Helper().WaitForPodReady(f.Namespace.Name, testPod.Name, time.Second*10)
		Expect(err).NotTo(HaveOccurred())

		testPod, err = f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.TODO(), testPod.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Ensure the corresponding CertificateRequest should exist with the correct spec")
		cr, err := f.Helper().WaitForCertificateRequestReady(testPod, time.Second)
		Expect(err).NotTo(HaveOccurred())

		err = util.CertificateRequestMatchesSpec(cr, testVolume.CSI.VolumeAttributes)
		Expect(err).NotTo(HaveOccurred())

		By("Ensure the certificate key pair exists in the pod and matches that in the CertificateRequest")
		certData, keyData, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, testPod.Name, "test-container-1", "/tls",
			testVolume.CSI.VolumeAttributes)
		Expect(err).NotTo(HaveOccurred())

		err = f.Helper().CertificateKeyMatch(cr, certData, keyData)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should create 30 pods with random containers, volumes, and attributes set", func() {
		// Generate random pods
		pods := make([]*corev1.Pod, 30)
		for i := range pods {
			pods[i] = f.RandomPod()
		}

		// Create random pods
		wg := new(sync.WaitGroup)
		wg.Add(len(pods))
		for i := range pods {
			go createPod(wg, f, i, pods)
		}
		wg.Wait()

		// Wait for all the pods to become ready
		wg.Add(len(pods))
		for i := range pods {
			go waitForPodToBecomeReady(wg, f, i, pods)
		}
		wg.Wait()

		// List all certificate requests that should be ready
		crs, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Ensure the pods volumes spec match CertificateRequest spec and the key
		// and cert match both in pod, and on host.
		wg.Add(len(pods))
		for i, pod := range pods {
			go testPod(wg, f, i, crs.Items, pod)
		}
		wg.Wait()

		// Ensure all pods can be deleted and their equivalent CertificateRequest deleted

		By("Ensuing all Pods can be deleted")
		wg.Add(len(pods))
		for i, pod := range pods {
			go deletePod(wg, f, i, pod)
		}
		wg.Wait()

		By("Ensuring all CertificateRequets have been deleted")
		crs, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(crs.Items) > 0 {
			Expect(fmt.Errorf("expected all CertificateRequests to be deleted, got=%+v", crs.Items)).NotTo(HaveOccurred())
		}
	})
})

func createPod(wg *sync.WaitGroup, f *framework.Framework, i int, pods []*corev1.Pod) {
	By(fmt.Sprintf("Creating a Pod %d", i))
	pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(context.TODO(), pods[i], metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Pod Created %d: %s", i, pod.Name))
	pods[i] = pod
	wg.Done()
}

func deletePod(wg *sync.WaitGroup, f *framework.Framework, i int, pod *corev1.Pod) {
	By(fmt.Sprintf("Deleting Pod %d: %s", i, pod.Name))
	err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	err = f.Helper().WaitForPodDeletion(pod.Namespace, pod.Name, time.Second*90)
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Pod Deleted %d: %s", i, pod.Name))
	wg.Done()
}

func waitForPodToBecomeReady(wg *sync.WaitGroup, f *framework.Framework, i int, pods []*corev1.Pod) {
	err := f.Helper().WaitForPodReady(f.Namespace.Name, pods[i].Name, time.Second*90)
	Expect(err).NotTo(HaveOccurred())

	readyPod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.TODO(), pods[i].Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	pods[i] = readyPod
	wg.Done()
}

func testPod(wg *sync.WaitGroup, f *framework.Framework, i int, crs []cmapi.CertificateRequest, pod *corev1.Pod) {
	By(fmt.Sprintf("Ensuring corresponding CertificateRequests exists with the correct spec %d: %s/%s", i, pod.Namespace, pod.Name))

	attributesMap := make(map[string]*map[string]string)

	// Not all defined volumes will be mounted. This means that the
	// NodePublishVolume will not be called and therefore no
	// CertificateRequest will be created. This is by design.
	for _, vol := range pod.Spec.Volumes {
		// Ignore non csi volumes
		if vol.VolumeSource.CSI == nil {
			continue
		}

		attributesMap[vol.Name] = &vol.CSI.VolumeAttributes
	}

	for _, container := range pod.Spec.Containers {
		By(fmt.Sprintf("Ensure the certificate key pairs exists in the pod's container and matches that in the CertificateRequest %d: %s/%s:%s", i, pod.Namespace, pod.Name, container.Name))
		for _, vol := range container.VolumeMounts {
			// Ignore non csi volumes
			if _, ok := attributesMap[vol.Name]; !ok {
				continue
			}

			// Find certificate request from list and ensure it is ready
			cr, err := f.Helper().FindCertificateRequestReady(crs, pod)
			Expect(err).NotTo(HaveOccurred())

			err = util.CertificateRequestMatchesSpec(cr, *attributesMap[vol.Name])
			Expect(err).NotTo(HaveOccurred())

			certData, keyData, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, container.Name, vol.MountPath,
				*attributesMap[vol.Name])

			err = f.Helper().CertificateKeyMatch(cr, certData, keyData)
			Expect(err).NotTo(HaveOccurred())
		}

		By(fmt.Sprintf("Ensure the certificate key pairs and metadata files exists in the host's data directory and matches that in the CertificateRequests %d: %s/%s",
			i, pod.Namespace, pod.Name))
		for _, vol := range container.VolumeMounts {
			// Ignore non csi volumes
			if _, ok := attributesMap[vol.Name]; !ok {
				continue
			}

			// Find certificate request from list and ensure it is ready
			_, err := f.Helper().FindCertificateRequestReady(crs, pod)
			Expect(err).NotTo(HaveOccurred())
		}
	}

	wg.Done()
}
