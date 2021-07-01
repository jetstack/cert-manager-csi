package keygen

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/jetstack/cert-manager/pkg/util/pki"

	"github.com/jetstack/cert-manager-csi/pkg/apis/defaults"
	"github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
	"github.com/jetstack/cert-manager-csi/pkg/apis/validation"
)

// Generator wraps the storage backend to allow for re-using private keys when
// re-issuing a certificate.
// It generates 2048-bit RSA private keys.
type Generator struct {
	Store *storage.Filesystem
}

// KeyForMetadata generates a 2048-bit RSA private key, or returns an existing one
// if the reuse private key attribute is present.
func (k *Generator) KeyForMetadata(meta metadata.Metadata) (crypto.PrivateKey, error) {
	attrs, err := defaults.SetDefaultAttributes(meta.VolumeContext)
	if err != nil {
		return nil, err
	}
	if err := validation.ValidateAttributes(attrs); err != nil {
		return nil, err
	}

	// By default, generate a new private key each time.
	if attrs[v1alpha1.ReusePrivateKey] != "true" {
		return new2048BitRSAKey()
	}

	bytes, err := k.Store.ReadFile(meta.VolumeID, attrs[v1alpha1.KeyFileKey])
	if errors.Is(err, storage.ErrNotFound) {
		// Generate a new key if one is not found on disk
		return new2048BitRSAKey()
	}
	if err != nil {
		return nil, err
	}

	pk, err := pki.DecodePrivateKeyBytes(bytes)
	if err != nil {
		// Generate a new key if the existing one cannot be decoded
		return new2048BitRSAKey()
	}

	return pk, nil
}

func new2048BitRSAKey() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
