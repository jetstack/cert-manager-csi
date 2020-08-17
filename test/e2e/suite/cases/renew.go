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
	"bytes"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilpointer "k8s.io/utils/pointer"

	csi "github.com/jetstack/cert-manager-csi/pkg/apis"
	"github.com/jetstack/cert-manager-csi/pkg/util"
	"github.com/jetstack/cert-manager-csi/test/e2e/framework"
)

var _ = framework.CasesDescribe("Normal certificate renew behaviour", func() {
	f := framework.NewDefaultFramework("renew-test")

	It("should renew certificates with the same private key if set", func() {
		pod, attr := newRenewingTestPod(f, map[string]string{"csi.cert-manager.io/reuse-private-key": "true"})

		By("Wait for certificate to be renewed twice but keep the same private key throughout")
		cert, key, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
		Expect(err).NotTo(HaveOccurred())

		for i := 0; i < 2; i++ {
			By(fmt.Sprintf("Wait for certificate to be renewed %d", i+1))

			var j int
			for {
				if j == 20 {
					Expect(errors.New("certificate did not renew in time")).NotTo(HaveOccurred())
				}

				time.Sleep(time.Second)

				By("Testing pod for new certificate file")
				newCert, newKey, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
				Expect(err).NotTo(HaveOccurred())

				if !bytes.Equal(key, newKey) {
					Expect(fmt.Errorf("expected renewed certificate to use same private key, exp=%s got=%s", key, newKey)).NotTo(HaveOccurred())
				}

				if !bytes.Equal(cert, newCert) {
					cert = newCert
					break
				}

				j++
			}
		}
	})

	It("should renew certificates with a new private key with no attribute set", func() {
		pod, attr := newRenewingTestPod(f, map[string]string{})

		By("Wait for certificate to be renewed and have a new private key")
		cert, key, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
		Expect(err).NotTo(HaveOccurred())

		for i := 0; i < 2; i++ {
			By(fmt.Sprintf("Wait for certificate to be renewed %d", i+1))

			var j int
			for {
				if j == 20 {
					Expect(errors.New("certificate did not renew in time")).NotTo(HaveOccurred())
				}

				time.Sleep(time.Second)

				By("Testing pod for new certificate file")
				newCert, newKey, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
				Expect(err).NotTo(HaveOccurred())

				if !bytes.Equal(cert, newCert) {
					if bytes.Equal(key, newKey) {
						Expect(fmt.Errorf("expected renewed certificate to not use same private key, old=%s new=%s", key, newKey)).NotTo(HaveOccurred())
					}

					cert = newCert
					key = newKey

					break
				}

				j++
			}
		}
	})

	It("should renew certificates with a new private key with attribute set to false", func() {
		pod, attr := newRenewingTestPod(f, map[string]string{"csi.cert-manager.io/reuse-private-key": "false"})

		By("Wait for certificate to be renewed and have a new private key")
		cert, key, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
		Expect(err).NotTo(HaveOccurred())

		for i := 0; i < 2; i++ {
			By(fmt.Sprintf("Wait for certificate to be renewed %d", i+1))

			var j int
			for {
				if j == 20 {
					Expect(errors.New("certificate did not renew in time")).NotTo(HaveOccurred())
				}

				time.Sleep(time.Second)

				By("Testing pod for new certificate file")
				newCert, newKey, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
				Expect(err).NotTo(HaveOccurred())

				if !bytes.Equal(cert, newCert) {
					if bytes.Equal(key, newKey) {
						Expect(fmt.Errorf("expected renewed certificate to not use same private key, old=%s new=%s", key, newKey)).NotTo(HaveOccurred())
					}

					cert = newCert
					key = newKey

					break
				}

				j++
			}
		}
	})

	It("should never renew certificates with disable-auto-renew attribute set to true", func() {
		pod, attr := newRenewingTestPod(f, map[string]string{"csi.cert-manager.io/disable-auto-renew": "true"})

		By("Wait for certificate to be renewed and have a new private key")
		cert, key, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
		Expect(err).NotTo(HaveOccurred())

		By("Wait for certificate to never be renewed")

		var j int
		for {
			if j == 20 {
				return
			}

			time.Sleep(time.Second)

			By("Testing pod for new certificate file")
			newCert, newKey, err := f.Helper().CertificateKeyInPodPath(f.Namespace.Name, pod.Name, pod.Spec.Containers[0].Name, "/tls", attr)
			Expect(err).NotTo(HaveOccurred())

			if !bytes.Equal(cert, newCert) {
				Expect(fmt.Errorf("expected certificate to never be renewed, exp=%s got=%s", cert, newCert)).NotTo(HaveOccurred())
			}

			if !bytes.Equal(key, newKey) {
				Expect(fmt.Errorf("expected key to never be renewed, exp=%s got=%s", key, newKey)).NotTo(HaveOccurred())
			}

			j++
		}
	})
})

func newRenewingTestPod(f *framework.Framework, extraAttributes map[string]string) (*corev1.Pod, map[string]string) {
	attributes := map[string]string{
		"csi.cert-manager.io/issuer-name":  f.Issuer.Name,
		"csi.cert-manager.io/issuer-kind":  f.Issuer.Kind,
		"csi.cert-manager.io/issuer-group": f.Issuer.Group,
		"csi.cert-manager.io/dns-names":    "a.example.com",
		"csi.cert-manager.io/duration":     "10s",
	}

	for k, v := range extraAttributes {
		attributes[k] = v
	}

	testVolume := corev1.Volume{
		Name: "tls",
		VolumeSource: corev1.VolumeSource{
			CSI: &corev1.CSIVolumeSource{
				Driver:           csi.GroupName,
				VolumeAttributes: attributes,
			},
		},
	}

	testPod := &corev1.Pod{
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
	testPod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(testPod)
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for Pod to become ready")
	err = f.Helper().WaitForPodReady(f.Namespace.Name, testPod.Name, time.Second*20)
	Expect(err).NotTo(HaveOccurred())

	testPod, err = f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Get(testPod.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	By("Ensure the corresponding CertificateRequest should exist with the correct spec")
	crName := util.BuildVolumeID(string(testPod.GetUID()), "tls")
	cr, err := f.Helper().WaitForCertificateRequestReady(f.Namespace.Name, crName, time.Second)
	Expect(err).NotTo(HaveOccurred())

	err = util.CertificateRequestMatchesSpec(cr, testVolume.CSI.VolumeAttributes)
	Expect(err).NotTo(HaveOccurred())

	return testPod, attributes
}
