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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
)

type KeyBundle struct {
	PrivateKey         crypto.Signer
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	PEM                []byte
}

func NewRSAKey() (*KeyBundle, error) {
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(sk),
		},
	)

	return &KeyBundle{
		PrivateKey:         sk,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PEM:                keyPEM,
	}, nil
}

func WriteFile(path string, b []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// We need to ensure unix permissions if the file already exists
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		return err
	}

	if err := ioutil.WriteFile(path, b, perm); err != nil {
		return err
	}

	// We need to ensure unix permissions if the file already exists
	return os.Chmod(path, perm)
}

func KeyPath(vol *csiapi.MetaData) string {
	return filepath.Join(vol.Path, "data", vol.Attributes[csiapi.KeyFileKey])
}

func CertPath(vol *csiapi.MetaData) string {
	return filepath.Join(vol.Path, "data", vol.Attributes[csiapi.CertFileKey])
}

func CAPath(vol *csiapi.MetaData) string {
	return filepath.Join(vol.Path, "data", vol.Attributes[csiapi.CAFileKey])
}
