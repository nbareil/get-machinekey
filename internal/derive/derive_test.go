package derive

import (
	"encoding/hex"
	"testing"
)

// Synthetic values from a disposable IIS lab. They are not production keys.
const (
	labMasterPrefix = "824EC2CB25F97051F59AE18B649E6D33114D9CD9F02601FE2F3F933D418E9A4D" +
		"B275166B0AF16C882DC7B9D36BC546BEB2DFC045E9012EA74BD46B3420340966" +
		"62D79D515AF5B9661A85A0596EAB2BA12D9DA0FF49A9F6EB"
	wantValidation = "F5DBAE08D5CEDA6920D4FA9016811DDFD5E3EAA8BD2F3EDAD908903BFE9DC396"
	wantDecryption = "663DBD3DA9D9D66CD7E5EE368796315F51A45295F4A7D5A7663A4D90710F1E30"
)

func TestASPNet45ApplicationKeyVariants(t *testing.T) {
	t.Parallel()
	master, err := hex.DecodeString(labMasterPrefix)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		flags          Flags
		wantValidation string
		wantDecryption string
	}{
		{"none", Flags{}, "7AE79E485B09DFAC20B8798A4A932D552EB4F4D664EB83CD173CFCAC2553847E", "FD6BC04B462830B6F41A98FB10241D5FE5D757A6FF90D3D8D405B0A1756080BD"},
		{"isolate_apps", Flags{IsolateApps: true}, "AD2736AC28EC3AD64E0E96DF5098D29ED5142E298E0AABD812C1B5790F26BAA7", "8FD8E938ACCE9AF4EEAD68119FA3E0AF8B48F8C26C5664AF54CE210262149FB1"},
		{"isolate_by_app_id", Flags{IsolateByAppID: true}, "0AF1FE5C99FEEDAA89D13CF722E55C52EAF8CE2CD209263A3F5746603E71E7EA", "1BFA0119918033A1BA23E9CEE550C95005275AD4EE63F6081A24035225E1CA94"},
		{"both", Flags{IsolateApps: true, IsolateByAppID: true}, wantValidation, wantDecryption},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validation, err := ApplicationKey(master, 32, tt.flags, "/", "/LM/W3SVC/1/ROOT")
			if err != nil {
				t.Fatal(err)
			}
			decryption, err := ApplicationKey(master, 0, tt.flags, "/", "/LM/W3SVC/1/ROOT")
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(validation); !equalFoldASCII(got, tt.wantValidation) {
				t.Fatalf("validation key = %s, want %s", got, tt.wantValidation)
			}
			if got := hex.EncodeToString(decryption); !equalFoldASCII(got, tt.wantDecryption) {
				t.Fatalf("decryption key = %s, want %s", got, tt.wantDecryption)
			}
		})
	}
}

func TestParseSetting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value   string
		autogen bool
		flags   Flags
	}{
		{"AutoGenerate,IsolateApps", true, Flags{IsolateApps: true}},
		{"AutoGenerate,IsolateApps,IsolateByAppId", true, Flags{IsolateApps: true, IsolateByAppID: true}},
		{"AABBCCDD", false, Flags{}},
		{"AABBCCDD,IsolateApps", false, Flags{IsolateApps: true}},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			autogen, flags, err := ParseSetting(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if autogen != tt.autogen || flags != tt.flags {
				t.Fatalf("got (%v, %#v), want (%v, %#v)", autogen, flags, tt.autogen, tt.flags)
			}
		})
	}
}

func TestExplicitKeyStripsLegacyModifiers(t *testing.T) {
	t.Parallel()
	got, err := ExplicitKey("AABBCCDD,IsolateApps,IsolateByAppId")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "aabbccdd" {
		t.Fatalf("got %x", got)
	}
}

func TestLegacyApplicationKeyVariants(t *testing.T) {
	t.Parallel()
	master, err := hex.DecodeString(labMasterPrefix)
	if err != nil {
		t.Fatal(err)
	}
	validation, decryption, err := LegacyBaseKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	const appHash = uint32(0x4EBA98B2)   // B298BA4E in little-endian key bytes.
	const appIDHash = uint32(0xB1BF55D3) // D355BFB1 in little-endian key bytes.

	tests := []struct {
		name           string
		flags          Flags
		wantValidation string
		wantDecryption string
	}{
		{"none", Flags{}, labMasterPrefix[:128], labMasterPrefix[128:]},
		{"isolate_apps", Flags{IsolateApps: true},
			"B298BA4E" + labMasterPrefix[8:128], "B298BA4E" + labMasterPrefix[136:]},
		{"isolate_by_app_id", Flags{IsolateByAppID: true},
			labMasterPrefix[:8] + "D355BFB1" + labMasterPrefix[16:128], labMasterPrefix[128:136] + "D355BFB1" + labMasterPrefix[144:]},
		{"both", Flags{IsolateApps: true, IsolateByAppID: true},
			"B298BA4ED355BFB1" + labMasterPrefix[16:128], "B298BA4ED355BFB1" + labMasterPrefix[144:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValidation, err := LegacyApplicationKey(validation, tt.flags, appHash, appIDHash)
			if err != nil {
				t.Fatal(err)
			}
			gotDecryption, err := LegacyApplicationKey(decryption, tt.flags, appHash, appIDHash)
			if err != nil {
				t.Fatal(err)
			}
			if !equalFoldASCII(hex.EncodeToString(gotValidation), tt.wantValidation) {
				t.Fatalf("validation = %X, want %s", gotValidation, tt.wantValidation)
			}
			if !equalFoldASCII(hex.EncodeToString(gotDecryption), tt.wantDecryption) {
				t.Fatalf("decryption = %X, want %s", gotDecryption, tt.wantDecryption)
			}
		})
	}
}

func TestApplicationKeyRejectsShortMaster(t *testing.T) {
	t.Parallel()
	if _, err := ApplicationKey(make([]byte, 63), 32, Flags{}, "/", "id"); err == nil {
		t.Fatal("expected short master key to fail")
	}
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
