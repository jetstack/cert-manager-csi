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

package app

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/jetstack/cert-manager-csi/pkg/filestore"
	"github.com/jetstack/cert-manager-csi/pkg/keygen"
	"github.com/jetstack/cert-manager-csi/pkg/requestgen"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/klog/klogr"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager-csi/cmd/app/options"
)

var (
	opts *options.Options
)

func init() {
	flag.Set("logtostderr", "true")

	flag.CommandLine.Parse([]string{})

	RootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	opts = options.AddFlags(RootCmd)
}

var RootCmd = &cobra.Command{
	Use:   "cert-manager-csi",
	Short: "Container Storage Interface driver to issue certificates from Cert-Manager",
	RunE: func(cmd *cobra.Command, args []string) error {

		log := klogr.New()

		restConfig, err := rest.InClusterConfig()
		if err != nil {
			panic("cannot load in-cluster config")
		}

		store, err := storage.NewFilesystem(log, opts.DataRoot)
		if err != nil {
			panic("failed to setup filesystem: " + err.Error())
		}

		keyGenerator := keygen.Generator{Store: store}
		writer := filestore.Writer{Store: store}

		d, err := driver.New(opts.Endpoint, log, driver.Options{
			DriverName:    opts.DriverName,
			DriverVersion: "v0.0.1",
			NodeID:        opts.NodeID,
			Store:         store,
			Manager: manager.NewManagerOrDie(manager.Options{
				Client:             cmclient.NewForConfigOrDie(restConfig),
				MetadataReader:     store,
				Clock:              clock.RealClock{},
				Log:                log,
				NodeID:             opts.NodeID,
				GeneratePrivateKey: keyGenerator.KeyForMetadata,
				GenerateRequest:    requestgen.RequestForMetadata,
				SignRequest:        signRequest,
				WriteKeypair:       writer.WriteKeypair,
			}),
		})
		if err != nil {
			return fmt.Errorf("failed to setup driver: " + err.Error())
		}

		if err := d.Run(); err != nil {
			return fmt.Errorf("failed running driver: " + err.Error())
		}

		return nil
	},
}

func signRequest(_ metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) ([]byte, error) {
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDer,
	}), nil
}
