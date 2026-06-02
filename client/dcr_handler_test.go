package client

import "testing"

func TestValidateEncryptionPair(t *testing.T) {
	cases := []struct {
		name    string
		alg     string
		enc     string
		wantErr bool
	}{
		{"both empty ok", "", "", false},
		{"alg only", "RSA-OAEP-256", "", true},
		{"enc only", "", "A256GCM", true},
		{"both supported", "RSA-OAEP-256", "A256GCM", false},
		{"unsupported alg", "BOGUS", "A256GCM", true},
		{"unsupported enc", "RSA-OAEP-256", "BOGUS-ENC", true},
		{"ecdh-es supported", "ECDH-ES", "A128GCM", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncryptionPair("test_field", tc.alg, tc.enc)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestSupportedJWEAlgsAndEncs_NonEmpty(t *testing.T) {
	if len(supportedJWEAlgs) == 0 {
		t.Errorf("supportedJWEAlgs is empty — DCR would reject every encryption config")
	}
	if len(supportedJWEEncs) == 0 {
		t.Errorf("supportedJWEEncs is empty — DCR would reject every encryption config")
	}
	// Sanity: the OIDC Core baseline must be supported.
	if !supportedJWEAlgs["RSA-OAEP-256"] {
		t.Errorf("RSA-OAEP-256 must be supported")
	}
	if !supportedJWEEncs["A256GCM"] {
		t.Errorf("A256GCM must be supported")
	}
}

// TestSupportedJWEAlgs_RejectsLegacyRSAOAEP locks in Vuln 8's fix.
// RSA-OAEP-MGF1-SHA1 is deprecated; the server must neither advertise
// it via discovery nor accept it during DCR.
func TestSupportedJWEAlgs_RejectsLegacyRSAOAEP(t *testing.T) {
	if supportedJWEAlgs["RSA-OAEP"] {
		t.Fatal("RSA-OAEP (MGF1-SHA1) must not be advertised; use RSA-OAEP-256 instead")
	}
	if err := validateEncryptionPair("id_token_encrypted_response", "RSA-OAEP", "A256GCM"); err == nil {
		t.Fatal("DCR must reject RSA-OAEP alg")
	}
}
