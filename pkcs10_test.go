package pkcs10

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestParseCertificateSigningRequest(t *testing.T) {
	block, _ := pem.Decode([]byte(csrNoAttrs))
	csr, err := ParseCertificateSigningRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Error parsing csr: %s", err)
	}

	if csr.Version != 0 {
		t.Errorf("Invalid CSR version. Got %d, want %d", csr.Version, 0)
	}

	expectedSubject := pkix.Name{
		Country:            []string{"NL"},
		Organization:       []string{"Σ Acme Co"},
		OrganizationalUnit: []string{"Unit"},
		Locality:           []string{"City"},
		Province:           []string{"Province"},
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "test.example.com",
		Names:              []pkix.AttributeTypeAndValue{},
	}

	if !reflect.DeepEqual(csr.Subject.Country, expectedSubject.Country) {
		t.Errorf("Incorrect country. Got %v, want %v", csr.Subject.Country, expectedSubject.Country)
	}

	if !reflect.DeepEqual(csr.Subject.Organization, expectedSubject.Organization) {
		t.Errorf("Incorrect organization. Got %v, want %v", csr.Subject.Organization, expectedSubject.Organization)
	}

	if !reflect.DeepEqual(csr.Subject.OrganizationalUnit, expectedSubject.OrganizationalUnit) {
		t.Errorf("Incorrect organizational unit. Got %v, want %v", csr.Subject.OrganizationalUnit, expectedSubject.OrganizationalUnit)
	}

	if !reflect.DeepEqual(csr.Subject.Locality, expectedSubject.Locality) {
		t.Errorf("Incorrect locality. Got %v, want %v", csr.Subject.Locality, expectedSubject.Locality)
	}

	if !reflect.DeepEqual(csr.Subject.Province, expectedSubject.Province) {
		t.Errorf("Incorrect province. Got %v, want %v", csr.Subject.Province, expectedSubject.Province)
	}

	if csr.Subject.CommonName != expectedSubject.CommonName {
		t.Errorf("Incorrect common name. Got %v, want %v", csr.Subject.CommonName, expectedSubject.CommonName)
	}
}

var csrNoAttrs = `-----BEGIN CERTIFICATE REQUEST-----
MIIBKDCB0wIBADBuMQswCQYDVQQGEwJOTDERMA8GA1UECAwIUHJvdmluY2UxDTAL
BgNVBAcMBENpdHkxEzARBgNVBAoMCs6jIEFjbWUgQ28xDTALBgNVBAsMBFVuaXQx
GTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAspkPScR9+ozUAK5qTRuKO2oTZCsj8osAO/uXeQremkzIK4sqgXR93sCLYpbl
OgjDMWh+8lxL9JNrocDmBB6dFQIDAQABoAAwDQYJKoZIhvcNAQEFBQADQQAZOqEg
pO+V1WGCGkBkGgmM2QlnrKaFYaRgYVlSEg7Tf+n9Wb8grcbQA8xo49z8qh2PbzgX
M7Ib4RDKnANBH0R+
-----END CERTIFICATE REQUEST-----
`
