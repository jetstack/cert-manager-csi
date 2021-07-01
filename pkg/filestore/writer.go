package filestore

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"

	"github.com/jetstack/cert-manager-csi/pkg/apis/defaults"
	"github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/apis/validation"
)

// Writer wraps the storage backend to allow access for writing data
type Writer struct {
	Store storage.Interface
}

func (w *Writer) WriteKeypair(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
	attrs, err := defaults.SetDefaultAttributes(meta.VolumeContext)
	if err != nil {
		return err
	}
	if err := validation.ValidateAttributes(attrs); err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
		},
	)

	nextIssuanceTime, err := calculateNextIssuanceTime(attrs, chain)
	if err != nil {
		return fmt.Errorf("calculating next issuance time: %w", err)
	}

	if err := w.Store.WriteFiles(meta.VolumeID, map[string][]byte{
		attrs[v1alpha1.KeyFileKey]:  keyPEM,
		attrs[v1alpha1.CertFileKey]: chain,
		attrs[v1alpha1.CAFileKey]:   ca,
	}); err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	meta.NextIssuanceTime = &nextIssuanceTime
	if err := w.Store.WriteMetadata(meta.VolumeID, meta); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

func calculateNextIssuanceTime(attrs map[string]string, chain []byte) (time.Time, error) {
	block, _ := pem.Decode(chain)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing issued certificate: %w", err)
	}

	actualDuration := crt.NotAfter.Sub(crt.NotBefore)
	// if not explicitly set, renew once a certificate is 2/3rds of the way through its lifetime
	renewBeforeNotAfter := actualDuration / 3
	if attrs[v1alpha1.RenewBeforeKey] != "" {
		renewBeforeDuration, err := time.ParseDuration(attrs[v1alpha1.RenewBeforeKey])
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing requested renew-before duration: %w", err)
		}

		// If the requested renewBefore would cause the certificate to be immediately re-issued,
		// ignore the requested renew before and renew 2/3rds of the way through its lifetime.
		if crt.NotBefore.Add(renewBeforeDuration).Before(crt.NotAfter) {
			renewBeforeNotAfter = renewBeforeDuration
		}
	}

	return crt.NotAfter.Add(-renewBeforeNotAfter), nil
}
