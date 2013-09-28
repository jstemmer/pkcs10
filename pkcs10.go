package pkcs10

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
