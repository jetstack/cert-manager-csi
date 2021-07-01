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

package defaults

import (
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
)

// SetDefaultAttributes will set default values on the given attribute map.
// It will not modify the attributes in-place, and instead will return a copy.
func SetDefaultAttributes(attrOriginal map[string]string) (map[string]string, error) {
	attr := make(map[string]string)
	for k, v := range attrOriginal {
		attr[k] = v
	}

	setDefaultIfEmpty(attr, csiapi.IssuerKindKey, cmapi.IssuerKind)
	setDefaultIfEmpty(attr, csiapi.IssuerGroupKey, certmanager.GroupName)

	setDefaultIfEmpty(attr, csiapi.IsCAKey, "false")
	setDefaultIfEmpty(attr, csiapi.DurationKey, cmapi.DefaultCertificateDuration.String())

	setDefaultIfEmpty(attr, csiapi.CAFileKey, "ca.pem")
	setDefaultIfEmpty(attr, csiapi.CertFileKey, "crt.pem")
	setDefaultIfEmpty(attr, csiapi.KeyFileKey, "key.pem")

	setDefaultIfEmpty(attr, csiapi.KeyUsagesKey, defaultKeyUsages())

	// TODO (@joshvanl): add a smarter defaulting mechanism
	dur, err := time.ParseDuration(attr[string(csiapi.DurationKey)])
	if err != nil {
		return nil, err
	}
	dur = dur / 3
	setDefaultIfEmpty(attr, csiapi.RenewBeforeKey, dur.String())

	return attr, nil
}

func setDefaultIfEmpty(attr map[string]string, k, v string) {
	if len(attr[string(k)]) == 0 {
		attr[string(k)] = v
	}
}

func defaultKeyUsages() string {
	var defKU []string

	for _, ku := range []cmapi.KeyUsage{
		cmapi.UsageDigitalSignature,
		cmapi.UsageKeyEncipherment,
	} {
		defKU = append(defKU, string(ku))
	}

	return strings.Join(defKU, ",")
}
