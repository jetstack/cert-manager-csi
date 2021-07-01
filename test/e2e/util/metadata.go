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
	"strings"
	"time"

	csiapi "github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func CertificateRequestMatchesSpec(cr *cmapi.CertificateRequest, attr map[string]string) error {
	var errs []string

	issuerName, ok := attr[csiapi.IssuerNameKey]
	if !ok {
		errs = append(errs, fmt.Sprintf("required %q not in volume attributes present", csiapi.IssuerNameKey))
	} else {
		if issuerName != cr.Spec.IssuerRef.Name {
			errs = append(errs, fmt.Sprintf("expected IssuerRef.Name to equal %q, got %q",
				issuerName, cr.Spec.IssuerRef.Name))
		}
	}

	issuerKind, ok := attr[csiapi.IssuerKindKey]
	if !ok || len(issuerKind) == 0 {
		issuerKind = "Issuer"
	}
	if issuerKind != cr.Spec.IssuerRef.Kind {
		errs = append(errs, fmt.Sprintf("expected IssuerRef.Kind to equal %q, got %q",
			issuerKind, cr.Spec.IssuerRef.Kind))
	}

	issuerGroup, ok := attr[csiapi.IssuerGroupKey]
	if !ok || len(issuerGroup) == 0 {
		issuerGroup = "cert-manager.io"
	}
	if issuerGroup != cr.Spec.IssuerRef.Group {
		errs = append(errs, fmt.Sprintf("expected IssuerRef.Group to equal %q, got %q",
			issuerGroup, cr.Spec.IssuerRef.Group))
	}

	isCA := attr[csiapi.IsCAKey]
	if len(isCA) == 0 {
		isCA = "false"
	}

	if isCA != "false" && isCA != "true" {
		errs = append(errs,
			fmt.Sprintf("isCA value must be 'true', 'false', or '', got %q",
				isCA))
	} else if (isCA == "true" && !cr.Spec.IsCA) || (isCA == "false" && cr.Spec.IsCA) {
		errs = append(errs,
			fmt.Sprintf("expected IsCA value to be %s, got %t",
				isCA, cr.Spec.IsCA))
	}

	duration, ok := attr[csiapi.DurationKey]
	if ok {
		durationT, err := time.ParseDuration(duration)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to parse attribute duration %q: %s",
				duration, err))
		} else if durationT != cr.Spec.Duration.Duration {
			errs = append(errs, fmt.Sprintf("unexpected requested duration, exp=%s got=%s",
				durationT, cr.Spec.Duration.Duration))
		}
	}

	if usages := KeyUsagesFromAttributes(attr); len(usages) > 0 {
		if !keyUsagesMatch(usages, cr.Spec.Usages) {
			errs = append(errs, fmt.Sprintf("key usages do not match, exp=%s got=%s",
				usages, cr.Spec.Usages))
		}
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(
		cr.Spec.Request)
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to parse certificate request PEM: %s",
			err))
	} else {
		commonName := attr[csiapi.CommonNameKey]
		if commonName != csr.Subject.CommonName {
			errs = append(errs, fmt.Sprintf("common name does not match, exp=%s got=%s",
				commonName, csr.Subject.CommonName))
		}

		dnsNames := ParseDNSNames(attr[csiapi.DNSNamesKey])
		if !StringsMatch(dnsNames, csr.DNSNames) {
			errs = append(errs, fmt.Sprintf("dns names do not match, exp=%s got=%s",
				dnsNames, csr.DNSNames))
		}

		ips := ParseIPAddresses(attr[csiapi.IPSANsKey])
		if !IPAddressesMatch(ips, csr.IPAddresses) {
			errs = append(errs, fmt.Sprintf("ip addresses do not match, exp=%v got=%v",
				ips, csr.IPAddresses))
		}

		uris, err := ParseURIs(attr[csiapi.URISANsKey])
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to parse URIs in attributes: %s",
				err))
		} else if !URIsMatch(uris, csr.URIs) {
			errs = append(errs, fmt.Sprintf("uris do not match, exp=%v got=%v",
				uris, csr.URIs))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("certificate request %q does not match volume attribute spec: %s",
			cr.Name, strings.Join(errs, ", "))
	}

	return nil
}
