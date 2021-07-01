package requestgen

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager-csi/pkg/apis/defaults"
	"github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/apis/validation"
)

func RequestForMetadata(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
	attrs, err := defaults.SetDefaultAttributes(meta.VolumeContext)
	if err != nil {
		return nil, err
	}
	if err := validation.ValidateAttributes(attrs); err != nil {
		return nil, err
	}

	namespace := attrs["csi.storage.k8s.io/pod.namespace"]

	uris, err := parseURIs(attrs[v1alpha1.URISANsKey])
	if err != nil {
		return nil, fmt.Errorf("invalid URI provided in %q attribute: %w", v1alpha1.URISANsKey, err)
	}

	ips := parseIPAddresses(attrs[v1alpha1.IPSANsKey])

	dnsNames := strings.Split(attrs[v1alpha1.DNSNamesKey], ",")
	commonName := attrs[v1alpha1.CommonNameKey]

	duration := cmapi.DefaultCertificateDuration
	if durStr, ok := attrs[v1alpha1.DurationKey]; ok {
		duration, err = time.ParseDuration(durStr)
		if err != nil {
			return nil, fmt.Errorf("invalid %q attribute: %w", v1alpha1.DurationKey, err)
		}
	}

	isCA := false
	if isCAStr, ok := attrs[v1alpha1.IsCAKey]; ok {
		switch strings.ToLower(isCAStr) {
		case "true":
			isCA = true
		case "false":
			isCA = false
		}
	}

	return &manager.CertificateRequestBundle{
		Request: &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			DNSNames:    dnsNames,
			IPAddresses: ips,
			URIs:        uris,
		},
		IsCA:      isCA,
		Namespace: namespace,
		Duration:  duration,
		Usages:    keyUsagesFromAttributes(attrs[v1alpha1.KeyUsagesKey]),
		IssuerRef: cmmeta.ObjectReference{
			Name:  attrs[v1alpha1.IssuerNameKey],
			Kind:  attrs[v1alpha1.IssuerKindKey],
			Group: attrs[v1alpha1.IssuerGroupKey],
		},
		Annotations: nil,
	}, nil
}

func parseIPAddresses(ips string) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	ipsS := strings.Split(ips, ",")

	var ipAddresses []net.IP

	for _, ipName := range ipsS {
		ip := net.ParseIP(ipName)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	return ipAddresses
}

func parseURIs(uris string) ([]*url.URL, error) {
	if len(uris) == 0 {
		return nil, nil
	}

	urisS := strings.Split(uris, ",")

	var urisURL []*url.URL

	for _, uriS := range urisS {
		uri, err := url.Parse(uriS)
		if err != nil {
			return nil, err
		}

		urisURL = append(urisURL, uri)
	}

	return urisURL, nil
}

func keyUsagesFromAttributes(usagesCSV string) []cmapi.KeyUsage {
	if len(usagesCSV) == 0 {
		return nil
	}

	var keyUsages []cmapi.KeyUsage
	for _, usage := range strings.Split(usagesCSV, ",") {
		keyUsages = append(keyUsages, cmapi.KeyUsage(strings.TrimSpace(usage)))
	}

	return keyUsages
}
