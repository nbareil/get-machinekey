package derive

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const keyLength = 32

type Flags struct {
	IsolateApps    bool
	IsolateByAppID bool
}

func ParseSetting(value string) (bool, Flags, error) {
	var flags Flags
	parts := strings.Split(value, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return false, Flags{}, errors.New("empty machineKey setting")
	}
	autogen := strings.TrimSpace(parts[0]) == "AutoGenerate"
	if !autogen {
		if _, err := ExplicitKey(parts[0]); err != nil {
			return false, Flags{}, err
		}
	}
	for index, part := range parts {
		if index == 0 {
			continue
		}
		switch strings.TrimSpace(part) {
		case "IsolateApps":
			flags.IsolateApps = true
		case "IsolateByAppId":
			flags.IsolateByAppID = true
		case "":
			return false, Flags{}, errors.New("empty machineKey setting")
		default:
			return false, Flags{}, fmt.Errorf("unsupported machineKey token %q", part)
		}
	}
	return autogen, flags, nil
}

func ExplicitKey(value string) ([]byte, error) {
	base := strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
	decoded, err := hex.DecodeString(base)
	if err != nil {
		return nil, fmt.Errorf("key is not valid hexadecimal: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("key is empty")
	}
	return decoded, nil
}

// ApplicationKey reproduces MachineKeyMasterKeyProvider's ASP.NET 4.5+
// SP800-108/HMAC-SHA-512 derivation. offset is 0 for encryption and 32 for
// validation.
func ApplicationKey(master []byte, offset int, flags Flags, applicationName, applicationID string) ([]byte, error) {
	if offset < 0 || len(master) < offset+keyLength {
		return nil, fmt.Errorf("auto-generated material is too short for offset %d", offset)
	}
	purposes := make([]string, 0, 2)
	if flags.IsolateApps {
		purposes = append(purposes, "IsolateApps: "+applicationName)
	}
	if flags.IsolateByAppID {
		purposes = append(purposes, "IsolateByAppId: "+applicationID)
	}
	return sp800108(master[offset:offset+keyLength], "MachineKeyDerivation", purposes), nil
}

func LegacyBaseKeys(master []byte) (validation, decryption []byte, err error) {
	if len(master) < 88 {
		return nil, nil, errors.New("auto-generated material is shorter than 88 bytes")
	}
	validation = append([]byte(nil), master[:64]...)
	decryption = append([]byte(nil), master[64:88]...)
	return validation, decryption, nil
}

// LegacyApplicationKey applies the pre-ASP.NET 4.5 isolation modifiers. The
// hash values must come from the target .NET Framework's
// StringComparer.InvariantCultureIgnoreCase implementation.
func LegacyApplicationKey(base []byte, flags Flags, applicationHash, applicationIDHash uint32) ([]byte, error) {
	result := append([]byte(nil), base...)
	if (flags.IsolateApps || flags.IsolateByAppID) && len(result) < 8 {
		return nil, errors.New("legacy key must be at least eight bytes when isolation is enabled")
	}
	if flags.IsolateApps {
		binary.LittleEndian.PutUint32(result[:4], applicationHash)
	}
	if flags.IsolateByAppID {
		binary.LittleEndian.PutUint32(result[4:8], applicationIDHash)
	}
	return result, nil
}

func sp800108(kdk []byte, primaryPurpose string, specificPurposes []string) []byte {
	context := make([]byte, 0)
	for _, purpose := range specificPurposes {
		encoded := []byte(purpose)
		context = append7BitEncodedInt(context, len(encoded))
		context = append(context, encoded...)
	}

	data := make([]byte, 0, 4+len(primaryPurpose)+1+len(context)+4)
	data = binary.BigEndian.AppendUint32(data, 1)
	data = append(data, primaryPurpose...)
	data = append(data, 0)
	data = append(data, context...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(kdk)*8))

	mac := hmac.New(sha512.New, kdk)
	_, _ = mac.Write(data)
	return append([]byte(nil), mac.Sum(nil)[:len(kdk)]...)
}

func append7BitEncodedInt(dst []byte, value int) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}
