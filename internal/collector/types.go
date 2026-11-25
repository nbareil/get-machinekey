package collector

import (
	"context"
	"time"

	"github.com/nbareil/get-machinekey/internal/iis"
)

const SchemaVersion = 2

type Options struct {
	ApplicationHostConfig string
	TargetURL             string
	Site                  string
}

type Report struct {
	SchemaVersion int                 `json:"schema_version"`
	CollectedAt   time.Time           `json:"collected_at"`
	Hostname      string              `json:"hostname"`
	TargetURL     string              `json:"target_url,omitempty"`
	Applications  []ApplicationResult `json:"applications"`
	Errors        []string            `json:"errors,omitempty"`
}

type ApplicationResult struct {
	Site                  string          `json:"site"`
	SiteID                string          `json:"site_id"`
	ApplicationPath       string          `json:"application_path"`
	ApplicationName       string          `json:"application_name"`
	ApplicationID         string          `json:"application_id"`
	ApplicationPool       string          `json:"application_pool"`
	WorkerIdentityType    string          `json:"worker_identity_type"`
	WorkerIdentity        string          `json:"worker_identity,omitempty"`
	WorkerIdentitySID     string          `json:"worker_identity_sid,omitempty"`
	ManagedRuntimeVersion string          `json:"managed_runtime_version,omitempty"`
	PhysicalPath          string          `json:"physical_path,omitempty"`
	Configuration         *iis.MachineKey `json:"configuration,omitempty"`
	KeySource             string          `json:"key_source,omitempty"`
	ASPNet45ValidationKey string          `json:"aspnet45_validation_key,omitempty"`
	ASPNet45DecryptionKey string          `json:"aspnet45_decryption_key,omitempty"`
	LegacyValidationBase  string          `json:"legacy_validation_base_key,omitempty"`
	LegacyDecryptionBase  string          `json:"legacy_decryption_base_key,omitempty"`
	LegacyValidationKey   string          `json:"legacy_validation_key,omitempty"`
	LegacyDecryptionKey   string          `json:"legacy_decryption_key,omitempty"`
	Errors                []string        `json:"errors,omitempty"`
}

func Collect(ctx context.Context, options Options) (Report, error) {
	return collect(ctx, options)
}
