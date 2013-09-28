package pkcs10

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

type certificateSigningRequest struct {
	Raw                      asn1.RawContent
	CertificationRequestInfo certificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	SignatureValue           asn1.BitString
}

type certificationRequestInfo struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo publicKeyInfo
	Attributes    asn1.RawValue
}

type CertificateSigningRequest struct {
	Raw                         []byte
	RawCertificationRequestInfo []byte
	RawSubject                  []byte
	RawSubjectPublicKeyInfo     []byte

	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm

	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	PublicKey          interface{}

	Version int
	Subject pkix.Name
}

func ParseCertificateSigningRequest(asn1Data []byte) (*CertificateSigningRequest, error) {
	var csr certificateSigningRequest
	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateSigningRequest(&csr)
}

func (c *CertificateSigningRequest) CheckSignature() (err error) {
	var hashType crypto.Hash

	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(c.RawCertificationRequestInfo)
	digest := h.Sum(nil)

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, c.Signature)
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(c.Signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("crypto/x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("crypto/x509: ECDSA verification failure")
		}
		return
	}
	return x509.ErrUnsupportedAlgorithm
}

func parseCertificateSigningRequest(in *certificateSigningRequest) (*CertificateSigningRequest, error) {
	out := new(CertificateSigningRequest)
	out.Raw = in.Raw
	out.RawCertificationRequestInfo = in.CertificationRequestInfo.Raw
	out.RawSubject = in.CertificationRequestInfo.Subject.FullBytes
	out.RawSubjectPublicKeyInfo = in.CertificationRequestInfo.SubjectPKInfo.Raw

	out.Signature = in.SignatureValue.RightAlign()
	out.SignatureAlgorithm = getSignatureAlgorithmFromOID(in.SignatureAlgorithm.Algorithm)

	out.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(in.CertificationRequestInfo.SubjectPKInfo.Algorithm.Algorithm)
	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.CertificationRequestInfo.SubjectPKInfo)
	if err != nil {
		return nil, err
	}

	out.Version = in.CertificationRequestInfo.Version

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(in.CertificationRequestInfo.Subject.FullBytes, &subject); err != nil {
		return nil, err
	}
	out.Subject.FillFromRDNSequence(&subject)

	return out, nil
}
