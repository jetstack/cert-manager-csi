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

package renew

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/util/pki"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
)

type walkDirT struct {
	volDirs []volDir

	expCertsToWatch []certToWatch
	expError        error
}

type volDir struct {
	name              string
	cert, key         []byte
	metaData          *csiapi.MetaData
	certPath, keyPath string
}

type certKeyPair struct {
	pk   *rsa.PrivateKey
	cert *x509.Certificate

	pkData, certData []byte
}

func TestWalkDir(t *testing.T) {
	keyCertPair1 := genKeyCertPair(t)
	keyCertPair2 := genKeyCertPair(t)

	tests := map[string]walkDirT{
		"if no directories exist then nothing returned and no error": {
			volDirs:         nil,
			expCertsToWatch: nil,
			expError:        nil,
		},

		"if no metadata file then nothing returned and no error": {
			volDirs: []volDir{
				{
					name:     "test-1",
					cert:     nil,
					key:      nil,
					certPath: "cert.pem",
					keyPath:  "key.pem",
				},
			},
			expCertsToWatch: nil,
			expError:        nil,
		},

		"if no cert and key data is bad then error": {
			volDirs: []volDir{
				{
					name: "test-1",
					cert: []byte("foo"),
					key:  []byte("bar"),
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
			},
			expCertsToWatch: nil,
			expError:        errors.New(`"csi-test-1": failed to parse key file: error decoding private key PEM block`),
		},

		"if key but bad cert data then error": {
			volDirs: []volDir{
				{
					name: "test-1",
					cert: []byte("foo"),
					key:  keyCertPair1.pkData,
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
			},
			expCertsToWatch: nil,
			expError:        errors.New(`"csi-test-1": failed to parse cert file: error decoding cert PEM block`),
		},

		"if a single cert key pair exist then return pair to watch": {
			volDirs: []volDir{
				{
					name: "test-1",
					cert: keyCertPair1.certData,
					key:  keyCertPair1.pkData,
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
			},
			expCertsToWatch: []certToWatch{
				{
					"csi-test-1",
					&csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
					keyCertPair1.cert.NotBefore,
					keyCertPair1.cert.NotAfter,
				},
			},
			expError: nil,
		},

		"if one volume good but the other bad then error": {
			volDirs: []volDir{
				{
					name: "test-1",
					cert: keyCertPair1.certData,
					key:  keyCertPair1.pkData,
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
				{
					name: "test-2",
					cert: keyCertPair1.certData,
					key:  []byte("foo"),
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
			},
			expCertsToWatch: nil,
			expError:        errors.New(`"csi-test-2": failed to parse key file: error decoding private key PEM block`),
		},

		"two good volumes should return two watches": {
			volDirs: []volDir{
				{
					name: "test-1",
					cert: keyCertPair1.certData,
					key:  keyCertPair1.pkData,
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
				},
				{
					name: "test-2",
					cert: keyCertPair2.certData,
					key:  keyCertPair2.pkData,
					metaData: &csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "foo.bar",
							csiapi.CertFileKey: "bar.foo",
						},
					},
				},
			},
			expCertsToWatch: []certToWatch{
				{
					"csi-test-1",
					&csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "key.pem",
							csiapi.CertFileKey: "cert.pem",
						},
					},
					keyCertPair1.cert.NotBefore,
					keyCertPair1.cert.NotAfter,
				},
				{
					"csi-test-2",
					&csiapi.MetaData{
						Attributes: map[string]string{
							csiapi.KeyFileKey:  "foo.bar",
							csiapi.CertFileKey: "bar.foo",
						},
					},
					keyCertPair2.cert.NotBefore,
					keyCertPair2.cert.NotAfter,
				},
			},
			expError: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(os.TempDir(), "cert-manager-csi-renew-")
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			defer os.RemoveAll(dir)

			for _, v := range test.volDirs {
				v.name = fmt.Sprintf("csi-%s", v.name)

				volPath := filepath.Join(dir, v.name)
				if err := os.Mkdir(volPath, 0700); err != nil {
					t.Error(err)
					t.FailNow()
				}

				if err := os.MkdirAll(filepath.Join(volPath, "data"), 0700); err != nil {
					t.Error(err)
					t.FailNow()
				}

				// if the data has been defined then write it to the specified path
				if v.metaData != nil {

					metaDataData, err := json.Marshal(v.metaData)
					if err != nil {
						t.Error(err)
						t.FailNow()
					}

					maybeWriteVolData(t, filepath.Join(volPath, "metadata.json"), metaDataData)
					maybeWriteVolData(t, filepath.Join(volPath, "data",
						v.metaData.Attributes[csiapi.CertFileKey]), v.cert)

					maybeWriteVolData(t, filepath.Join(volPath, "data",
						v.metaData.Attributes[csiapi.KeyFileKey]), v.key)
				}
			}

			r := New(dir, nil)
			certsToWatch, err := r.walkDir()
			errMatch(t, test.expError, err)

			sortCertsToWatch(test.expCertsToWatch)
			sortCertsToWatch(certsToWatch)

			certsToWatchMatch(t, test.expCertsToWatch, certsToWatch)
		})
	}
}

type watchFileT struct {
	expectCall  bool
	killWatcher bool
	renewBefore string
	expError    error

	watchingVols map[string]chan struct{}
}

func TestWatchCert(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), "cert-manager-csi-renew-")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer os.RemoveAll(dir)

	tests := map[string]watchFileT{
		"if volume already being watched then should exit with no error": {
			watchingVols: map[string]chan struct{}{"test-id": nil},
			expError:     nil,
			expectCall:   false,
		},

		"if unable to parse duration then should error": {
			expError:    errors.New(`failed to watch certificate "test-id": failed to parse renew before: time: invalid duration foo`),
			expectCall:  false,
			renewBefore: "foo",
		},

		"if renewBefore is now then expect call": {
			expError:    nil,
			expectCall:  true,
			renewBefore: "59.9s",
		},

		"if watcher is killed then expect no renewal": {
			expError:    nil,
			expectCall:  false,
			renewBefore: "0s",
			killWatcher: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var called bool

			renF := func(vol *csiapi.MetaData) (*x509.Certificate, error) {
				called = true

				if !test.expectCall {
					return nil, errors.New("go unepexted call")
				}

				return new(x509.Certificate), nil
			}

			r := New(dir, renF)
			if test.watchingVols != nil {
				r.watchingVols = test.watchingVols
			}

			metaData := &csiapi.MetaData{
				ID: "test-id",
				Attributes: map[string]string{
					csiapi.RenewBeforeKey: test.renewBefore,
				},
			}

			err := r.WatchCert(metaData, time.Now(), time.Now().Add(time.Second*60))
			errMatch(t, test.expError, err)

			if test.killWatcher == true {
				r.KillWatcher(metaData.ID)
			}

			time.Sleep(time.Second / 2)

			if test.expectCall != called {
				t.Errorf("unexpected renewal call, exp=%t got=%t",
					test.expectCall, called)
			}
		})
	}
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func genKeyCertPair(t *testing.T) *certKeyPair {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	pkData := pki.EncodePKCS1PrivateKey(pk)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute),
		SerialNumber:          serialNumber,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certData, cert, err := pki.SignCertificate(cert, cert, &pk.PublicKey, pk)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	return &certKeyPair{
		pk:       pk,
		pkData:   pkData,
		cert:     cert,
		certData: certData,
	}
}

func certsToWatchMatch(t *testing.T, exp, got []certToWatch) {
	if len(exp) != len(got) {
		t.Errorf("got unexpected certs to watch, exp=%+v got=%+v",
			exp, got)
		return
	}

	var missmatch bool
	for i := range exp {
		if exp[i].base != got[i].base {
			missmatch = true
			break
		}

		if !reflect.DeepEqual(exp[i].metaData, got[i].metaData) {
			missmatch = true
			break
		}

		if exp[i].notAfter.String() != got[i].notAfter.String() {
			missmatch = true
			break
		}
	}

	if missmatch {
		t.Errorf("got unexpected certs to watch, exp=%v got=%v",
			exp, got)
	}
}

func maybeWriteVolData(t *testing.T, path string, data []byte) {
	if len(data) > 0 {
		if err := ioutil.WriteFile(path, data, 0644); err != nil {
			t.Error(err)
			t.FailNow()
		}
	}
}

func errMatch(t *testing.T, exp, got error) {
	if exp != nil && (got == nil || exp.Error() != got.Error()) {
		t.Errorf("got unexpected error, exp=%s got=%v", exp, got)
	}

	if exp == nil && got != nil {
		t.Errorf("got unexpected error, exp=nil got=%s", got)
	}
}

func sortCertsToWatch(certsToWatch []certToWatch) {
	sort.SliceStable(certsToWatch, func(i, j int) bool {
		return certsToWatch[i].base < certsToWatch[j].base
	})
}
