//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/nbareil/get-machinekey/internal/derive"
	"github.com/nbareil/get-machinekey/internal/iis"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	aspnetRegistryPath          = `Software\Microsoft\ASP.NET\4.0.30319.0`
	lsaSecretName               = `L$ASP.NETAutoGenKeysV44.0.30319.0`
	policyGetPrivateInformation = 0x00000004
	effectiveConfigTimeout      = 20 * time.Second
)

var (
	advapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy          = advapi32.NewProc("LsaOpenPolicy")
	procLsaRetrievePrivateData = advapi32.NewProc("LsaRetrievePrivateData")
	procLsaClose               = advapi32.NewProc("LsaClose")
	procLsaFreeMemory          = advapi32.NewProc("LsaFreeMemory")
	procLsaNtStatusToWinError  = advapi32.NewProc("LsaNtStatusToWinError")
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func collect(ctx context.Context, options Options) (Report, error) {
	configPath := options.ApplicationHostConfig
	if configPath == "" {
		configPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config")
	}
	file, err := os.Open(configPath)
	if err != nil {
		return Report{}, fmt.Errorf("open applicationHost.config: %w", err)
	}
	defer file.Close()

	apps, err := iis.ParseApplicationHost(file, func(value string) string {
		expanded, expandErr := registry.ExpandString(value)
		if expandErr != nil {
			return value
		}
		return expanded
	})
	if err != nil {
		return Report{}, err
	}
	if options.TargetURL != "" {
		apps, err = iis.ResolveURL(apps, options.TargetURL, options.Site)
		if err != nil {
			return Report{}, err
		}
	} else if options.Site != "" {
		return Report{}, errors.New("-site requires a target URL")
	}
	hostname, hostnameErr := os.Hostname()
	report := Report{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      hostname,
		TargetURL:     options.TargetURL,
		Applications:  make([]ApplicationResult, 0, len(apps)),
	}
	if hostnameErr != nil {
		report.Errors = append(report.Errors, "determine hostname: "+hostnameErr.Error())
	}
	appcmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "appcmd.exe")
	for _, app := range apps {
		report.Applications = append(report.Applications, collectApplication(ctx, appcmd, app))
	}
	return report, nil
}

func collectApplication(ctx context.Context, appcmd string, app iis.Application) ApplicationResult {
	result := ApplicationResult{
		Site:                  app.Site,
		SiteID:                app.SiteID,
		ApplicationPath:       app.Path,
		ApplicationName:       app.ApplicationName,
		ApplicationID:         app.ApplicationID,
		ApplicationPool:       app.Pool,
		WorkerIdentityType:    app.IdentityType,
		WorkerIdentity:        identityAccount(app),
		ManagedRuntimeVersion: app.RuntimeVersion,
		PhysicalPath:          app.PhysicalPath,
	}

	sid, err := identitySID(result.WorkerIdentity)
	if err != nil {
		result.Errors = append(result.Errors, "resolve worker identity SID: "+err.Error())
	} else {
		result.WorkerIdentitySID = sid
	}

	config, err := effectiveMachineKey(ctx, appcmd, app)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.Configuration = &config

	validationAutogen, validationFlags, err := derive.ParseSetting(config.ValidationKey)
	if err != nil {
		result.Errors = append(result.Errors, "parse validationKey setting: "+err.Error())
		return result
	}
	decryptionAutogen, decryptionFlags, err := derive.ParseSetting(config.DecryptionKey)
	if err != nil {
		result.Errors = append(result.Errors, "parse decryptionKey setting: "+err.Error())
		return result
	}

	var validationBase, decryptionBase []byte
	validationSource := "effective IIS configuration"
	decryptionSource := "effective IIS configuration"
	if !validationAutogen {
		validationBase, err = derive.ExplicitKey(config.ValidationKey)
		if err != nil {
			result.Errors = append(result.Errors, "decode explicit validationKey: "+err.Error())
			return result
		}
		result.LegacyValidationBase = formatKey(validationBase)
		if validationFlags == (derive.Flags{}) {
			result.ASPNet45ValidationKey = formatKey(validationBase)
		}
	}
	if !decryptionAutogen {
		decryptionBase, err = derive.ExplicitKey(config.DecryptionKey)
		if err != nil {
			result.Errors = append(result.Errors, "decode explicit decryptionKey: "+err.Error())
			return result
		}
		result.LegacyDecryptionBase = formatKey(decryptionBase)
		if decryptionFlags == (derive.Flags{}) {
			result.ASPNet45DecryptionKey = formatKey(decryptionBase)
		}
	}

	if validationAutogen || decryptionAutogen {
		if strings.HasPrefix(strings.ToLower(app.RuntimeVersion), "v2.") {
			result.Errors = append(result.Errors, "auto-generated machine keys for ASP.NET 2.0/3.5 are not supported")
			return result
		}
		if app.RuntimeVersion == "" {
			result.Errors = append(result.Errors, "application pool has no managed runtime; auto-generated ASP.NET machine keys are not applicable")
			return result
		}
		if result.WorkerIdentitySID == "" {
			result.Errors = append(result.Errors, "cannot locate auto-generated material without the worker identity SID")
			return result
		}

		master, source, findErr := findMasterKey(result.WorkerIdentitySID, result.WorkerIdentitySID == "S-1-5-18")
		if findErr != nil {
			result.Errors = append(result.Errors, findErr.Error())
			return result
		}
		legacyValidation, legacyDecryption, legacyErr := derive.LegacyBaseKeys(master)
		if legacyErr != nil {
			result.Errors = append(result.Errors, "extract legacy base keys: "+legacyErr.Error())
			return result
		}
		if validationAutogen {
			validationSource = source
			validationBase = legacyValidation
			result.LegacyValidationBase = formatKey(validationBase)
			key, keyErr := derive.ApplicationKey(master, 32, validationFlags, app.ApplicationName, app.ApplicationID)
			if keyErr != nil {
				result.Errors = append(result.Errors, "derive ASP.NET 4.5+ validation key: "+keyErr.Error())
			} else {
				result.ASPNet45ValidationKey = formatKey(key)
			}
		}
		if decryptionAutogen {
			decryptionSource = source
			decryptionBase = legacyDecryption
			result.LegacyDecryptionBase = formatKey(decryptionBase)
			key, keyErr := derive.ApplicationKey(master, 0, decryptionFlags, app.ApplicationName, app.ApplicationID)
			if keyErr != nil {
				result.Errors = append(result.Errors, "derive ASP.NET 4.5+ decryption key: "+keyErr.Error())
			} else {
				result.ASPNet45DecryptionKey = formatKey(key)
			}
		}
	}
	if validationSource == decryptionSource {
		result.KeySource = validationSource
	} else {
		result.KeySource = "validation: " + validationSource + "; decryption: " + decryptionSource
	}

	var applicationHash, applicationIDHash uint32
	if validationFlags.IsolateApps || validationFlags.IsolateByAppID || decryptionFlags.IsolateApps || decryptionFlags.IsolateByAppID {
		applicationHash, applicationIDHash, err = frameworkLegacyHashes(ctx, app.ApplicationName, app.ApplicationID)
		if err != nil {
			result.Errors = append(result.Errors, "derive legacy isolation hashes: "+err.Error())
			return result
		}
	}
	legacyValidation, legacyErr := derive.LegacyApplicationKey(validationBase, validationFlags, applicationHash, applicationIDHash)
	if legacyErr != nil {
		result.Errors = append(result.Errors, "derive legacy validation key: "+legacyErr.Error())
	} else {
		result.LegacyValidationKey = formatKey(legacyValidation)
	}
	legacyDecryption, legacyErr := derive.LegacyApplicationKey(decryptionBase, decryptionFlags, applicationHash, applicationIDHash)
	if legacyErr != nil {
		result.Errors = append(result.Errors, "derive legacy decryption key: "+legacyErr.Error())
	} else {
		result.LegacyDecryptionKey = formatKey(legacyDecryption)
	}
	return result
}

func formatKey(value []byte) string {
	return strings.ToUpper(hex.EncodeToString(value))
}

func identityAccount(app iis.Application) string {
	switch strings.ToLower(app.IdentityType) {
	case "applicationpoolidentity":
		return `IIS APPPOOL\` + app.Pool
	case "localsystem":
		return `NT AUTHORITY\SYSTEM`
	case "localservice":
		return `NT AUTHORITY\LOCAL SERVICE`
	case "networkservice":
		return `NT AUTHORITY\NETWORK SERVICE`
	case "specificuser":
		return app.IdentityUser
	default:
		return app.IdentityUser
	}
}

func identitySID(account string) (string, error) {
	if account == "" {
		return "", errors.New("application pool has no resolvable identity account")
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

func effectiveMachineKey(ctx context.Context, appcmd string, app iis.Application) (iis.MachineKey, error) {
	queryCtx, cancel := context.WithTimeout(ctx, effectiveConfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(queryCtx, appcmd, "list", "config", iis.ConfigURL(app), "/section:system.web/machineKey", "/config:*")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			message := strings.TrimSpace(string(exitErr.Stderr))
			if message != "" {
				return iis.MachineKey{}, fmt.Errorf("query effective machineKey configuration: %s", message)
			}
		}
		return iis.MachineKey{}, fmt.Errorf("query effective machineKey configuration: %w", err)
	}
	config, err := iis.ParseMachineKey(output)
	if err != nil {
		return iis.MachineKey{}, err
	}
	return config, nil
}

func frameworkLegacyHashes(ctx context.Context, applicationName, applicationID string) (uint32, uint32, error) {
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	const command = `$a=[Environment]::GetEnvironmentVariable('GET_MACHINEKEY_APP_NAME');` +
		`$i=[Environment]::GetEnvironmentVariable('GET_MACHINEKEY_APP_ID');` +
		`$c=[Globalization.CultureInfo]::InvariantCulture;` +
		`[Console]::Out.Write(([StringComparer]::InvariantCultureIgnoreCase.GetHashCode($a)).ToString($c)+','+([StringComparer]::InvariantCultureIgnoreCase.GetHashCode($i)).ToString($c))`
	hashCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(hashCtx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Env = setEnvironment(os.Environ(), map[string]string{
		"GET_MACHINEKEY_APP_NAME": applicationName,
		"GET_MACHINEKEY_APP_ID":   applicationID,
	})
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			message := strings.TrimSpace(string(exitErr.Stderr))
			if message != "" {
				return 0, 0, fmt.Errorf("Windows PowerShell failed: %s", message)
			}
		}
		return 0, 0, fmt.Errorf("run Windows PowerShell .NET Framework hash helper: %w", err)
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("unexpected Windows PowerShell hash output")
	}
	appHash, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse application-name hash: %w", err)
	}
	appIDHash, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse application-ID hash: %w", err)
	}
	return uint32(int32(appHash)), uint32(int32(appIDHash)), nil
}

func setEnvironment(base []string, updates map[string]string) []string {
	result := make([]string, 0, len(base)+len(updates))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if found {
			if _, replace := lookupFold(updates, name); replace {
				continue
			}
		}
		result = append(result, entry)
	}
	for name, value := range updates {
		result = append(result, name+"="+value)
	}
	return result
}

func lookupFold(values map[string]string, name string) (string, bool) {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func findMasterKey(sid string, allowLSA bool) ([]byte, string, error) {
	userPath := sid + `\` + aspnetRegistryPath
	if value, view, err := readRegistryBinary(registry.USERS, userPath, "AutoGenKeyV4"); err == nil {
		return value, `HKU\` + userPath + `\AutoGenKeyV4 (` + view + ` view)`, nil
	}
	machinePath := aspnetRegistryPath + `\AutoGenKeys\` + sid
	if value, view, err := readRegistryBinary(registry.LOCAL_MACHINE, machinePath, "AutoGenKeyV4"); err == nil {
		return value, `HKLM\` + machinePath + `\AutoGenKeyV4 (` + view + ` view)`, nil
	}
	if allowLSA {
		if value, err := retrieveLSASecret(lsaSecretName); err == nil {
			return value, `LSA private data ` + lsaSecretName, nil
		}
		return nil, "", fmt.Errorf("auto-generated material not found in HKU, HKLM fallback, or LSA private data for SID %s", sid)
	}
	return nil, "", fmt.Errorf("auto-generated material not found in HKU or HKLM fallback for SID %s", sid)
}

func readRegistryBinary(root registry.Key, path, valueName string) ([]byte, string, error) {
	views := []struct {
		name string
		flag uint32
	}{
		{"64-bit", registry.WOW64_64KEY},
		{"32-bit", registry.WOW64_32KEY},
	}
	var lastErr error
	for _, view := range views {
		key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|view.flag)
		if err != nil {
			lastErr = err
			continue
		}
		value, _, valueErr := key.GetBinaryValue(valueName)
		key.Close()
		if valueErr != nil {
			lastErr = valueErr
			continue
		}
		if len(value) == 0 {
			lastErr = errors.New("registry value is empty")
			continue
		}
		return value, view.name, nil
	}
	return nil, "", lastErr
}

func retrieveLSASecret(name string) ([]byte, error) {
	attributes := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var policy uintptr
	status, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attributes)), policyGetPrivateInformation, uintptr(unsafe.Pointer(&policy)))
	if status != 0 {
		return nil, lsaStatusError(status)
	}
	defer procLsaClose.Call(policy)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, err
	}
	secretName := lsaUnicodeString{
		Length:        uint16((len(nameUTF16) - 1) * 2),
		MaximumLength: uint16(len(nameUTF16) * 2),
		Buffer:        namePtr,
	}
	var secretPtr unsafe.Pointer
	status, _, _ = procLsaRetrievePrivateData.Call(policy, uintptr(unsafe.Pointer(&secretName)), uintptr(unsafe.Pointer(&secretPtr)))
	if status != 0 {
		return nil, lsaStatusError(status)
	}
	if secretPtr == nil {
		return nil, errors.New("LSA returned an empty secret pointer")
	}
	defer procLsaFreeMemory.Call(uintptr(secretPtr))
	secret := (*lsaUnicodeString)(secretPtr)
	if secret.Length == 0 || secret.Buffer == nil {
		return nil, errors.New("LSA private data is empty")
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(secret.Buffer)), int(secret.Length))...), nil
}

func lsaStatusError(status uintptr) error {
	winError, _, _ := procLsaNtStatusToWinError.Call(status)
	return syscall.Errno(winError)
}
