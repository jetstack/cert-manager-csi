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

package certmanager

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/util"
)

type CertManager struct {
	cmClient cmclient.Interface
}

func New() (*CertManager, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	cmClient, err := cmclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &CertManager{
		cmClient: cmClient,
	}, nil
}

func (c *CertManager) EnsureCertificate(vol *csiapi.MetaData, keyBundle *util.KeyBundle) (*x509.Certificate, error) {
	attr := vol.Attributes
	namespace := attr[csiapi.CSIPodNamespaceKey]

	// Check if a certificate request exists and matches the current volume spec
	ok, err := c.checkExistingCertificateRequest(vol)
	if err != nil {
		return nil, err
	}

	// Not ok so create a new certificate request
	if !ok {
		if err := c.createNewCertificateRequest(vol, keyBundle); err != nil {
			return nil, err
		}
	}

	glog.Infof("cert-manager: waiting for CertificateRequest to become ready %s", vol.ID)
	cr, err := c.waitForCertificateRequestReady(vol.ID, namespace, time.Second*30)
	if err != nil {
		return nil, err
	}

	if err := util.WriteMetaDataFile(vol); err != nil {
		return nil, err
	}

	glog.V(4).Infof("cert-manager: metadata written to file %s", filepath.Join(vol.Path, csiapi.MetaDataFileName))

	certPath := util.CertPath(vol)

	if err := util.WriteFile(certPath, cr.Status.Certificate, 0644); err != nil {
		return nil, err
	}

	if len(cr.Status.CA) > 0 {
		caPath := util.CAPath(vol)

		if err := util.WriteFile(caPath, cr.Status.CA, 0644); err != nil {
			return nil, err
		}

		glog.Infof("cert-manager: CA certificate written to file %s", caPath)
	}

	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return nil, err
	}

	glog.Infof("cert-manager: certificate written to file %s", certPath)

	keyPath := util.KeyPath(vol)
	if err := util.WriteFile(keyPath, keyBundle.PEM, 0644); err != nil {
		return nil, fmt.Errorf("faild to write key data to file: %s", err)
	}

	glog.Infof("cert-manager: private key written to file: %s", keyPath)

	return cert, nil
}

func (c *CertManager) createNewCertificateRequest(vol *csiapi.MetaData, keyBundle *util.KeyBundle) error {
	attr := vol.Attributes
	namespace := attr[csiapi.CSIPodNamespaceKey]

	uris, err := util.ParseURIs(attr[csiapi.URISANsKey])
	if err != nil {
		return err
	}

	ips := util.ParseIPAddresses(attr[csiapi.IPSANsKey])

	dnsNames := strings.Split(attr[csiapi.DNSNamesKey], ",")
	commonName := attr[csiapi.CommonNameKey]

	duration := cmapi.DefaultCertificateDuration
	if durStr, ok := attr[csiapi.DurationKey]; ok {
		duration, err = time.ParseDuration(durStr)
		if err != nil {
			return err
		}
	}

	isCA := false
	if isCAStr, ok := attr[csiapi.IsCAKey]; ok {
		switch strings.ToLower(isCAStr) {
		case "true":
			isCA = true
		case "false":
			isCA = false
		}
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		URIs:               uris,
		PublicKey:          keyBundle.PrivateKey.Public(),
		PublicKeyAlgorithm: keyBundle.PublicKeyAlgorithm,
		SignatureAlgorithm: keyBundle.SignatureAlgorithm,
	}

	csrPEM, err := util.EncodeCSR(csr, keyBundle.PrivateKey)
	if err != nil {
		return err
	}
	// Build certificate request for volume
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vol.ID,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion:         "core/v1",
					BlockOwnerDeletion: util.BoolPointer(true),
					Controller:         util.BoolPointer(false),
					Kind:               "Pod",
					Name:               vol.Attributes[csiapi.CSIPodNamespaceKey],
					UID:                types.UID(vol.Attributes[csiapi.CSIPodUIDKey]),
				},
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM: csrPEM,
			IsCA:   isCA,
			Duration: &metav1.Duration{
				Duration: duration,
			},
			Usages: util.KeyUsagesFromAttributes(attr),
			IssuerRef: cmmeta.ObjectReference{
				Name:  attr[csiapi.IssuerNameKey],
				Kind:  attr[csiapi.IssuerKindKey],
				Group: attr[csiapi.IssuerGroupKey],
			},
		},
	}

	_, err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(namespace).Create(cr)
	if err != nil {
		return err
	}

	glog.Infof("cert-manager: created CertificateRequest %s", vol.ID)

	return nil
}

func (c *CertManager) RenewCertificate(vol *csiapi.MetaData) (*x509.Certificate, error) {
	var err error
	var keyBundle *util.KeyBundle

	glog.Infof("cert-manager: renewing certicate %s", vol.ID)

	if b, ok := vol.Attributes[csiapi.ReusePrivateKey]; !ok || b != "true" {
		keyBundle, err = util.NewRSAKey()
		if err != nil {
			return nil, err
		}

	} else {

		keyBytes, err := ioutil.ReadFile(util.KeyPath(vol))

		if err != nil {
			return nil, err
		}

		sk, err := pki.DecodePKCS1PrivateKeyBytes(keyBytes)
		if err != nil {
			return nil, err
		}

		keyBundle = &util.KeyBundle{
			PEM:                keyBytes,
			PrivateKey:         sk,
			SignatureAlgorithm: x509.SHA256WithRSA,
			PublicKeyAlgorithm: x509.RSA,
		}
	}

	namespace := vol.Attributes[csiapi.CSIPodNamespaceKey]
	err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(namespace).Delete(vol.ID, &metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}

	cert, err := c.EnsureCertificate(vol, keyBundle)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *CertManager) checkExistingCertificateRequest(vol *csiapi.MetaData) (bool, error) {
	namespace := vol.Attributes[csiapi.CSIPodNamespaceKey]

	// get current certificate request
	cr, err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(namespace).Get(vol.ID, metav1.GetOptions{})
	// certificate request doesn't exist so create a new one
	if k8sErrors.IsNotFound(err) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	// If certificate request doesn't match the volume spec then delete the current one
	if err := util.CertificateRequestMatchesSpec(cr, vol.Attributes); err != nil {
		glog.Infof("cert-manager: deleting existing CertificateRequest since it doesn't match spec %s: %s", vol.ID, err)
		err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(namespace).Delete(vol.ID, &metav1.DeleteOptions{})
		if err != nil {
			return false, err
		}

		return false, nil
	}

	return true, nil
}

func (c *CertManager) waitForCertificateRequestReady(name, ns string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var cr *cmapi.CertificateRequest
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {

			glog.V(4).Infof("cert-manager: polling CertificateRequest %s/%s for ready status", name, ns)

			var err error
			cr, err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}

			if reason, failed := util.CertificateRequestFailed(cr); failed {
				return false, fmt.Errorf("certificate request marked as failed: %s", reason)
			}

			if !util.CertificateRequestReady(cr) {
				return false, nil
			}

			return true, nil
		},
	)

	if err != nil {
		return cr, err
	}

	return cr, nil
}
